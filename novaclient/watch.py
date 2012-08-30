# Copyright 2010 Jacob Kaplan-Moss
# Copyright 2011 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Return some stats from the OpenStack Nova API in gource format
"""

import argparse
#import glob
#import httplib2
#import imp
#import itertools
import logging
#import os
#import pkgutil
import sys
import time

import novaclient
from novaclient import client
from novaclient import exceptions as exc
#import novaclient.extension
from novaclient import utils
#from novaclient.v1_1 import shell as shell_v1_1

DEFAULT_OS_COMPUTE_API_VERSION = "1.1"
DEFAULT_NOVA_ENDPOINT_TYPE = 'publicURL'
DEFAULT_NOVA_SERVICE_TYPE = 'compute'

logger = logging.getLogger(__name__)


class NovaClientArgumentParser(argparse.ArgumentParser):

    def __init__(self, *args, **kwargs):
        super(NovaClientArgumentParser, self).__init__(*args, **kwargs)

    def error(self, message):
        """error(message: string)

        Prints a usage message incorporating the message to stderr and
        exits.
        """
        self.print_usage(sys.stderr)
        #FIXME(lzyeval): if changes occur in argparse.ArgParser._check_value
        choose_from = ' (choose from'
        progparts = self.prog.partition(' ')
        self.exit(2, "error: %(errmsg)s\nTry '%(mainp)s help %(subp)s'"
                     " for more information.\n" %
                     {'errmsg': message.split(choose_from)[0],
                      'mainp': progparts[0],
                      'subp': progparts[2]})


class OpenStackComputeShell(object):

    def get_base_parser(self):
        parser = NovaClientArgumentParser(
            prog='nova',
            description=__doc__.strip(),
            epilog='See "nova help COMMAND" '\
                   'for help on a specific command.',
            add_help=False,
            formatter_class=OpenStackHelpFormatter,
        )

        # Global arguments
        parser.add_argument('-h', '--help',
            action='store_true',
            help=argparse.SUPPRESS,
        )

        parser.add_argument('--version',
                            action='version',
                            version=novaclient.__version__)

        parser.add_argument('--debug',
            default=False,
            action='store_true',
            help="Print debugging output")

        parser.add_argument('--no-cache',
            default=utils.env('OS_NO_CACHE', default=False),
            action='store_true',
            help="Don't use the auth token cache.")

        parser.add_argument('--timings',
            default=False,
            action='store_true',
            help="Print call timing info")

        parser.add_argument('--os-username',
            metavar='<auth-user-name>',
            default=utils.env('OS_USERNAME', 'NOVA_USERNAME'),
            help='Defaults to env[OS_USERNAME].')

        parser.add_argument('--os-password',
            metavar='<auth-password>',
            default=utils.env('OS_PASSWORD', 'NOVA_PASSWORD'),
            help='Defaults to env[OS_PASSWORD].')

        parser.add_argument('--os-tenant-name',
            metavar='<auth-tenant-name>',
            default=utils.env('OS_TENANT_NAME', 'NOVA_PROJECT_ID'),
            help='Defaults to env[OS_TENANT_NAME].')

        parser.add_argument('--os-auth-url',
            metavar='<auth-url>',
            default=utils.env('OS_AUTH_URL', 'NOVA_URL'),
            help='Defaults to env[OS_AUTH_URL].')

        parser.add_argument('--os-region-name',
            metavar='<region-name>',
            default=utils.env('OS_REGION_NAME', 'NOVA_REGION_NAME'),
            help='Defaults to env[OS_REGION_NAME].')

        parser.add_argument('--os-auth-system',
            metavar='<auth-system>',
            default=utils.env('OS_AUTH_SYSTEM'),
            help='Defaults to env[OS_AUTH_SYSTEM].')

        parser.add_argument('--service-type',
            metavar='<service-type>',
            help='Defaults to compute for most actions')

        parser.add_argument('--service-name',
            metavar='<service-name>',
            default=utils.env('NOVA_SERVICE_NAME'),
            help='Defaults to env[NOVA_SERVICE_NAME]')

        parser.add_argument('--volume-service-name',
            metavar='<volume-service-name>',
            default=utils.env('NOVA_VOLUME_SERVICE_NAME'),
            help='Defaults to env[NOVA_VOLUME_SERVICE_NAME]')

        parser.add_argument('--endpoint-type',
            metavar='<endpoint-type>',
            default=utils.env('NOVA_ENDPOINT_TYPE',
                        default=DEFAULT_NOVA_ENDPOINT_TYPE),
            help='Defaults to env[NOVA_ENDPOINT_TYPE] or '
                    + DEFAULT_NOVA_ENDPOINT_TYPE + '.')

        parser.add_argument('--os-compute-api-version',
            metavar='<compute-api-ver>',
            default=utils.env('OS_COMPUTE_API_VERSION',
                default=DEFAULT_OS_COMPUTE_API_VERSION),
            help='Accepts 1.1, defaults to env[OS_COMPUTE_API_VERSION].')

        parser.add_argument('--insecure',
            default=utils.env('NOVACLIENT_INSECURE', default=False),
            action='store_true',
            help="Explicitly allow novaclient to perform \"insecure\" "
                 "SSL (https) requests. The server's certificate will "
                 "not be verified against any certificate authorities. "
                 "This option should be used with caution.")

        parser.add_argument('--bypass-url',
            metavar='<bypass-url>',
            dest='bypass_url',
            help="Use this API endpoint instead of the Service Catalog")

        return parser

    def setup_debugging(self, debug):
        if not debug:
            return

        streamhandler = logging.StreamHandler()
        streamformat = "%(levelname)s (%(module)s:%(lineno)d) %(message)s"
        streamhandler.setFormatter(logging.Formatter(streamformat))
        logger.setLevel(logging.DEBUG)
        logger.addHandler(streamhandler)

        httplib2.debuglevel = 1

    def main(self, argv):
        parser = self.get_base_parser()
        (options, args) = parser.parse_known_args(argv)
        self.setup_debugging(options.debug)

        if options.help and len(args) == 0:
            parser.print_help()
            return 0

        if not options.os_username:
            raise exc.CommandError("You must provide a username "
                    "via either --os-username or env[OS_USERNAME]")

        if not options.os_password:
            raise exc.CommandError("You must provide a password "
                    "via either --os-password or via "
                    "env[OS_PASSWORD]")

        if not options.os_tenant_name:
            raise exc.CommandError("You must provide a tenant name "
                    "via either --os-tenant-name or "
                    "env[OS_TENANT_NAME]")

        if not options.os_auth_url:
            if options.os_auth_system and options.os_auth_system != 'keystone':
                options.os_auth_url = \
                    client.get_auth_system_url(os_auth_system)

        if not options.os_auth_url:
                raise exc.CommandError("You must provide an auth url "
                        "via either --os-auth-url or env[OS_AUTH_URL] "
                        "or specify an auth_system which defines a "
                        "default url with --os-auth-system "
                        "or env[OS_AUTH_SYSTEM")

        if (options.os_compute_api_version and
                options.os_compute_api_version != '1.0'):
            if not options.os_tenant_name:
                raise exc.CommandError("You must provide a tenant name "
                        "via either --os-tenant-name or env[OS_TENANT_NAME]")

            if not options.os_auth_url:
                raise exc.CommandError("You must provide an auth url "
                        "via either --os-auth-url or env[OS_AUTH_URL]")

        # Make a compute client
        if not options.endpoint_type:
            options.endpoint_type = DEFAULT_NOVA_ENDPOINT_TYPE

        if not options.service_type:
            options.service_type = DEFAULT_NOVA_SERVICE_TYPE

        self.cc = client.Client(
            options.os_compute_api_version,
            options.os_username,
            options.os_password,
            options.os_tenant_name,
            options.os_auth_url,
            options.insecure,
            region_name=options.os_region_name,
            endpoint_type=options.endpoint_type,
            service_type=options.service_type,
            service_name=options.service_name,
            volume_service_name=options.volume_service_name,
            auth_system=options.os_auth_system,
            http_log_debug=options.debug
        )

        try:
            self.cc.authenticate()
        except exc.Unauthorized:
            raise exc.CommandError("Invalid OpenStack Nova credentials.")
        except exc.AuthorizationFailure:
            raise exc.CommandError("Unable to authorize user")

        # Make a volume client
        if not options.endpoint_type:
            options.endpoint_type = DEFAULT_NOVA_ENDPOINT_TYPE

        options.service_type = 'volume'

        self.vc = client.Client(
            options.os_compute_api_version,
            options.os_username,
            options.os_password,
            options.os_tenant_name,
            options.os_auth_url,
            options.insecure,
            region_name=options.os_region_name,
            endpoint_type=options.endpoint_type,
            service_type=options.service_type,
            service_name=options.service_name,
            volume_service_name=options.volume_service_name,
            auth_system=options.os_auth_system,
            http_log_debug=options.debug
        )

        try:
            self.vc.authenticate()
        except exc.Unauthorized:
            raise exc.CommandError("Invalid OpenStack Nova credentials.")
        except exc.AuthorizationFailure:
            raise exc.CommandError("Unable to authorize user")

        # do watch loop
        self.hosts = {}
        self.vms = {}
        self.vols = {}
        self.search_opts = {
            'all_tenants': 1,
        }
        while True:
            self.update_hosts(self.hosts)
            self.update_vms(self.vms)
            self.update_vols(self.vols)
            time.sleep(10)

    def update_hosts(self, hosts):
        old_hosts = hosts.keys()
        new_hosts = []
        host_list = self.cc.hosts.list_all()
        # First add anything that exists now
        for h in host_list:
            new_hosts.append(h.human_id)
            if h.human_id not in old_hosts:
                hosts[h.human_id] = h.host_name+'|'+h.service
                self.log("A", "os/%s/h.%s" % (h.host_name, h.service))

        # Remove anything that used to exist
        for id in old_hosts:
            if id not in new_hosts:
                self.log("D", "os/%s/h.%s" % hosts[id].split('|'))
                del hosts[id]


    def update_vms(self, vms):
        old_vms = vms.keys()
        new_vms = []
        servers = self.cc.servers.list(search_opts=self.search_opts)
        # First add anything that exists now
        for s in servers:
            new_vms.append(s.id)
            if s.id not in old_vms:
                vms[s.id] = s.name
                self.log("A", "vm/%s.vm" % s.name)

        # Remove anything that used to exist
        for id in old_vms:
            if id not in new_vms:
                self.log("D", "vm/%s.vm" % vms[id])
                del vms[id]

    def update_vols(self, vols):
        old_vols = vols.keys()
        new_vols = []
        volumes = self.vc.volumes.list()
        # First add anything that exists now
        for v in volumes:
            new_vols.append(v.id)
            if v.id not in old_vols:
                vols[v.id] = v.display_name
                self.log("A", "vol/%s.vol" % v.display_name)

        # Remove anything that used to exist
        for id in old_vols:
            if id not in new_vols:
                self.log("D", "vol/%s.vol" % vols[id])
                del vols[id]

    def log(self, kind, file):
        # http://code.google.com/p/gource/wiki/CustomLogFormat
        timestamp = int(time.time())
        username = 'ubuntu'
        # kind should be (A)dded, (M)odified or (D)eleted
        print "%d|%s|%s|%s" % (timestamp, username, kind, file)
        sys.stdout.flush()

    def _dump_timings(self, timings):
        class Tyme(object):
            def __init__(self, url, seconds):
                self.url = url
                self.seconds = seconds
        results = [Tyme(url, end - start) for url, start, end in timings]
        total = 0.0
        for tyme in results:
            total += tyme.seconds
        results.append(Tyme("Total", total))
        utils.print_list(results, ["url", "seconds"], sortby_index=None)

    @utils.arg('command', metavar='<subcommand>', nargs='?',
                    help='Display help for <subcommand>')
    def do_help(self, args):
        """
        Display help about this program or one of its subcommands.
        """
        if args.command:
            if args.command in self.subcommands:
                self.subcommands[args.command].print_help()
            else:
                raise exc.CommandError("'%s' is not a valid subcommand" %
                                       args.command)
        else:
            self.parser.print_help()


# I'm picky about my shell help.
class OpenStackHelpFormatter(argparse.HelpFormatter):
    def start_section(self, heading):
        # Title-case the headings
        heading = '%s%s' % (heading[0].upper(), heading[1:])
        super(OpenStackHelpFormatter, self).start_section(heading)


def main():
    try:
        OpenStackComputeShell().main(sys.argv[1:])

    except Exception, e:
        logger.debug(e, exc_info=1)
        print >> sys.stderr, "ERROR: %s" % str(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
