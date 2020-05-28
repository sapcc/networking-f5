# Copyright 2019 SAP SE
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import sys
from collections import defaultdict

import netaddr
from f5.bigip import ManagementRoot
from icontrol.exceptions import iControlUnexpectedHTTPError
from oslo_log import log as logging
from prometheus_client import Summary, Counter
from requests import Timeout, ConnectionError
from six.moves.urllib import parse
from tenacity import retry_if_exception_type, retry, \
    wait_incrementing, stop_after_attempt

from networking_f5 import constants
from networking_f5.agent.f5_agent import F5Backend

LOG = logging.getLogger(__name__)

RETRY_ATTEMPTS = 3
RETRY_INITIAL_DELAY = 1
RETRY_BACKOFF = 5
RETRY_MAX = 3


class PromInstance(object):
    def __init__(self):
        # Prometheus counters
        self.vlan_update = Counter('vlan_update', 'Updates of vlans')
        self.vlan_create = Counter('vlan_create', 'Creations of vlans')
        self.vlan_delete = Counter('vlan_delete', 'Deletions of vlans')
        self.selfip_update = Counter('selfip_update', 'Updates of selfips')
        self.selfip_create = Counter('selfip_create', 'Creations of selfips')
        self.selfip_delete = Counter('selfip_delete', 'Deletions of selfips')
        self.route_domain_update = Counter('route_domain_update', 'Updates of route_domains')
        self.route_domain_create = Counter('route_domain_create', 'Creations of route_domains')
        self.route_domain_delete = Counter('route_domain_delete', 'Deletions of route_domains')
        self.route_update = Counter('route_update', 'Updates of routes')
        self.route_create = Counter('route_create', 'Creations of routes')
        self.route_delete = Counter('route_delete', 'Deletions of routes')


PROM_INSTANCE = PromInstance()


class F5iControlRestBackend(F5Backend):
    def __init__(self, cfg, uri, device_mappings):
        super(F5iControlRestBackend, self).__init__(cfg, uri, device_mappings)
        self.conf = cfg
        self.device = parse.urlparse(uri)
        self.devices = []  # SelfIP Ports
        self.device_mappings = device_mappings
        self.mgmt = None
        self._login()

    def _login(self):
        if not self.device.username or not self.device.password:
            LOG.error("Need to specify valid F5.devices configuration: "
                      "http(s)://<username>:<password>@hostname,...")
            sys.exit(1)

        self.mgmt = ManagementRoot(
            self.device.hostname,
            self.device.username,
            self.device.password,
            token=True,
            verify=self.conf.F5.https_verify
        )

        for interface in self.device_mappings.values():
            if self.mgmt.tm.net.trunks.trunk.exists(name=interface):
                trunk = self.mgmt.tm.net.trunks.trunk.load(name=interface)
                self.mac = trunk.macAddress
                break

    def get_mac(self):
        return self.mac

    def get_host(self):
        if self.conf.F5.override_hostname:
            return self.conf.F5.override_hostname
        return self.device.hostname

    def is_active(self):
        def get_device_name(bigip):
            devices = bigip.tm.cm.devices.get_collection()
            for device in devices:
                if device.selfDevice == 'true':
                    return device.name

            return None

        act = self.mgmt.tm.cm.devices.device.load(
            name=get_device_name(self.mgmt), partition='Common')
        return act.failoverState.lower() == 'active'

    @staticmethod
    def _prefix(collection, prefix, replace_hyphen=False):
        if replace_hyphen:
            return {
                (prefix + name).replace('-', '_'): val
                for name, val
                in collection.items()
            }
        return {
            prefix + name: val
            for name, val
            in collection.items()
        }

    @staticmethod
    def _prefix_vlans(collection):
        return {
            '{}{}'.format(constants.PREFIX_VLAN, val['tag']): val
            for val in collection.values()
        }

    def try_delete_object(self, o_type, name):
        try:

            o = getattr(self.mgmt.tm.net, o_type + 's')
            o = getattr(o, o_type).load(name=name)
            o.delete()
        except iControlUnexpectedHTTPError:
            pass

    REQUEST_TIME_SYNC_VLANS = Summary(
        'sync_vlan_seconds',
        'Time spent processing vlans')

    @REQUEST_TIME_SYNC_VLANS.time()
    def _sync_vlans(self, vlans):
        print(vlans)
        new_vlans = self._prefix_vlans(vlans)
        v = self.mgmt.tm.net.vlans
        for old_vlan in v.get_collection():
            # Migration case
            if old_vlan.name.startswith('net-'):
                try:
                    old_vlan.delete()
                except iControlUnexpectedHTTPError:
                    pass
                continue

            # Not managed by agent
            if not old_vlan.name.startswith(constants.PREFIX_VLAN):
                pass

            # Update
            elif old_vlan.name in new_vlans:
                vlan = new_vlans.pop(old_vlan.name)
                if old_vlan.tag != vlan['tag'] or old_vlan.mtu != vlan['mtu']:
                    old_vlan.tag = vlan['tag']
                    old_vlan.mtu = vlan['mtu']
                    old_vlan.hardwareSyncookie = 'enabled'
                    old_vlan.update()
                    PROM_INSTANCE.vlan_update.inc()

            # orphaned
            else:
                try:
                    old_vlan.delete()
                    PROM_INSTANCE.vlan_delete.inc()
                except iControlUnexpectedHTTPError:
                    pass

        # New ones
        for name, vlan in new_vlans.items():
            v.vlan.create(name=name, partition='Common', hardwareSyncookie='enabled',
                          tag=vlan['tag'], mtu=vlan['mtu'])
            PROM_INSTANCE.vlan_create.inc()

    REQUEST_TIME_SYNC_SELFIPS = Summary(
        'sync_selfip_seconds',
        'Time spent processing selfips')

    @REQUEST_TIME_SYNC_SELFIPS.time()
    def _sync_selfips(self, selfips):
        def convert_ip(selfip):
            if selfip['ip_address'].find('/') >= 0:
                selfip['prefixlen'] = netaddr.IPNetwork(selfip['ip_address']).prefixlen
                selfip['ip_address'] = str(netaddr.IPNetwork(selfip['ip_address']).ip)

            return '{}%{}/{}'.format(
                    selfip['ip_address'],
                    selfip['tag'],
                    selfip['prefixlen']
                )

        def get_vlan_path(selfip):
            return '/Common/{}{}'.format(
                constants.PREFIX_VLAN,
                selfip['tag']
            )

        prefixed_selfips = self._prefix(
            selfips, constants.PREFIX_SELFIP)
        sips = self.mgmt.tm.net.selfips.get_collection()
        self.devices = [sip.name[len(constants.PREFIX_SELFIP):] for sip in sips
                        if sip.name.startswith(constants.PREFIX_SELFIP)]
        for old_sip in sips:
            # Not managed by agent
            if not old_sip.name.startswith(constants.PREFIX_SELFIP):
                continue

            # Update
            elif old_sip.name in prefixed_selfips:
                selfip = prefixed_selfips.pop(old_sip.name)
                if old_sip.vlan != get_vlan_path(
                        selfip) or old_sip.address != convert_ip(selfip):
                    old_sip.vlan = get_vlan_path(selfip)
                    old_sip.address = convert_ip(selfip)
                    old_sip.update()
                    PROM_INSTANCE.selfip_update.inc()

            # orphaned
            else:
                try:
                    old_sip.delete()
                    PROM_INSTANCE.selfip_delete.inc()
                except iControlUnexpectedHTTPError:
                    self.try_delete_object('route', old_sip.name)

        # New ones
        for name, selfip in prefixed_selfips.items():
            if self.get_host() != selfip['host']:
                continue

            self.mgmt.tm.net.selfips.selfip.create(
                name=name,
                partition='Common',
                vlan='{}{}'.format(constants.PREFIX_VLAN, selfip['tag']),
                address=convert_ip(selfip),
            )
            PROM_INSTANCE.selfip_create.inc()

    REQUEST_TIME_SYNC_ROUTEDOMAINS = Summary(
        'sync_routedomains_seconds',
        'Time spent processing routedomains')

    @REQUEST_TIME_SYNC_ROUTEDOMAINS.time()
    def _sync_routedomains(self, vlans):
        prefixed_nets = self._prefix(vlans, constants.PREFIX_NET)
        rds = self.mgmt.tm.net.route_domains
        for rd in rds.get_collection():
            # Not managed by agent
            if not rd.name.startswith(constants.PREFIX_NET):
                pass

            # Update
            elif rd.name in prefixed_nets:
                vlan = prefixed_nets.pop(rd.name)
                vlans = ['/Common/{}{}'.format(constants.PREFIX_VLAN, vlan['tag'])]
                if getattr(rd, 'vlans', []) != vlans or rd.id != vlan['tag']:
                    rd.vlans = vlans
                    rd.id = vlan['tag']
                    rd.update()
                    PROM_INSTANCE.route_domain_update.inc()

            # orphaned
            else:
                try:
                    rd.delete()
                    PROM_INSTANCE.route_domain_delete.inc()
                except iControlUnexpectedHTTPError:
                    pass

        # New ones
        for name, vlan in prefixed_nets.items():
            try:
                rds.route_domain.create(
                    name=name, partition='Common', id=vlan['tag'],
                    vlans=['/Common/{}{}'.format(constants.PREFIX_VLAN, vlan['tag'])])
                PROM_INSTANCE.route_domain_create.inc()
            except iControlUnexpectedHTTPError:
                # Try deleting selfip first and let it resync next time
                self.try_delete_object('selfip', name)

    REQUEST_TIME_SYNC_ROUTES = Summary(
        'sync_routes_seconds',
        'Time spent processing routes')

    @REQUEST_TIME_SYNC_ROUTES.time()
    def _sync_routes(self, selfips):
        prefixed_selfips = self._prefix(
            selfips, constants.PREFIX_SELFIP)

        # We only need one route per network, remove larger gateway IPs
        tmp = defaultdict(list)
        for val in prefixed_selfips.values():
            tmp[val['network_id']].append(int(netaddr.IPAddress(val['gateway_ip'])))

        prefixed_selfips = dict((key, val) for key, val in prefixed_selfips.items()
                                if int(netaddr.IPAddress(val['gateway_ip'])) == min(tmp[val['network_id']]))

        routes = self.mgmt.tm.net.routes
        for route in routes.get_collection():
            # Not managed by agent
            if not route.name.startswith(constants.PREFIX_SELFIP):
                pass

            # Update
            elif route.name in prefixed_selfips:
                selfip = prefixed_selfips.pop(route.name)
                gateway = '{}%{}'.format(
                    selfip['gateway_ip'],
                    selfip['tag']
                )
                network = 'default%{}'.format(selfip['tag'])
                if route.gw != gateway or route.network != network:
                    route.gw = gateway
                    route.network = network
                    route.update()
                    PROM_INSTANCE.route_update.inc()

            # orphaned
            else:
                try:
                    route.delete()
                    PROM_INSTANCE.route_delete.inc()
                except iControlUnexpectedHTTPError:
                    pass

        # New ones
        for name, selfip in prefixed_selfips.items():
            gateway = '{}%{}'.format(
                selfip['gateway_ip'],
                selfip['tag']
            )
            network = 'default%{}'.format(selfip['tag'])
            routes.route.create(network=network, gw=gateway,
                name=name, partition='Common')
            PROM_INSTANCE.route_create.inc()

    SYNC_ALL_EXCEPTIONS = Counter(
        'sync_exceptions',
        'Exceptions during sync_all')

    @retry(
        retry=retry_if_exception_type((Timeout, ConnectionError)),
        wait=wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=stop_after_attempt(RETRY_ATTEMPTS)
    )
    @SYNC_ALL_EXCEPTIONS.count_exceptions()
    def sync_all(self, vlans, selfips):
        try:
            LOG.debug("Syncing vlans %s", [vlan['tag'] for vlan in vlans.values()])
            self._sync_vlans(vlans)
        except iControlUnexpectedHTTPError as e:
            LOG.exception(e)

        try:
            LOG.debug("Syncing routedomains %s", [vlan['tag'] for vlan in vlans.values()])
            self._sync_routedomains(vlans)
        except iControlUnexpectedHTTPError as e:
            LOG.exception(e)

        try:
            LOG.debug("Syncing selfips %s", [selfip['ip_address'] for selfip in selfips.values()])
            self._sync_selfips(selfips)
        except iControlUnexpectedHTTPError as e:
            LOG.exception(e)

        try:
            LOG.debug("Syncing routes %s", [selfip['gateway_ip'] for selfip in selfips.values()])
            self._sync_routes(selfips)
        except iControlUnexpectedHTTPError as e:
            LOG.exception(e)

    def plug_interface(self, network_segment, device):
        name = constants.PREFIX_SELFIP + device
        if self.mgmt.tm.net.selfips.selfip.exists(name=name):
            return True

        # wait till sync-loop processed the port
        return False

    def get_devices(self):
        return self.devices
