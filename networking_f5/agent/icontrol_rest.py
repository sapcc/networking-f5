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

PROM_ACTION = Counter('networking_f5_action',
                      'Update/Creations/Deletion of l2 entities', ['type', 'action'])
REQUEST_TIME_SYNC_ROUTES = Summary(
    'networking_f5_sync_routes_seconds', 'Time spent processing routes')
REQUEST_TIME_SYNC_VLANS = Summary(
    'networking_f5_sync_vlan_seconds', 'Time spent processing vlans')
REQUEST_TIME_SYNC_SELFIPS = Summary(
    'networking_f5_sync_selfip_seconds', 'Time spent processing selfips')
REQUEST_TIME_SYNC_ROUTEDOMAINS = Summary(
    'networking_f5_sync_routedomains_seconds', 'Time spent processing routedomains')
REQUEST_TIME_SYNC_ALL = Summary(
    'networking_f5_sync_all', 'Time spent processing sync_all')


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
            parse.unquote(self.device.password),
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

    def delete_object(self, o_type, name):
        o_type = o_type.replace('routedomain', 'route_domain')
        o = getattr(self.mgmt.tm.net, o_type + 's')
        o = getattr(o, o_type).load(name=name)
        o.delete()

    @retry(
        retry=retry_if_exception_type(iControlUnexpectedHTTPError),
        wait=wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=stop_after_attempt(RETRY_ATTEMPTS)
    )
    @REQUEST_TIME_SYNC_VLANS.time()
    def _sync_vlans(self, vlans):
        orphaned = []
        new_vlans = self._prefix_vlans(vlans)
        v = self.mgmt.tm.net.vlans
        for old_vlan in v.get_collection():
            try:
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
                    if (old_vlan.tag != vlan['tag'] or old_vlan.mtu != vlan['mtu'] or
                            old_vlan.synFloodRateLimit != self.conf.F5.syn_flood_rate_limit or
                            old_vlan.syncacheThreshold != self.conf.F5.syncache_threshold):
                        old_vlan.tag = vlan['tag']
                        old_vlan.mtu = vlan['mtu']
                        old_vlan.hardwareSyncookie = 'enabled' if self.conf.F5.hardware_syncookie else 'disabled'
                        old_vlan.synFloodRateLimit = self.conf.F5.syn_flood_rate_limit
                        old_vlan.syncacheThreshold = self.conf.F5.syncache_threshold
                        PROM_ACTION.labels(type='vlan', action='update').inc()
                        old_vlan.update()


                # orphaned
                else:
                    orphaned.append(old_vlan)
            except iControlUnexpectedHTTPError as e:
                LOG.exception(e)

        # New ones
        for name, vlan in new_vlans.items():
            PROM_ACTION.labels(type='vlan', action='create').inc()
            v.vlan.create(name=name, partition='Common',
                          tag=vlan['tag'], mtu=vlan['mtu'],
                          hardwareSyncookie='enabled' if self.conf.F5.hardware_syncookie else 'disabled',
                          synFloodRateLimit=self.conf.F5.syn_flood_rate_limit,
                          syncacheThreshold=self.conf.F5.syncache_threshold
            )

        return orphaned

    @retry(
        retry=retry_if_exception_type(iControlUnexpectedHTTPError),
        wait=wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=stop_after_attempt(RETRY_ATTEMPTS)
    )
    @REQUEST_TIME_SYNC_SELFIPS.time()
    def _sync_selfips(self, selfips):
        orphaned = []
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
            try:
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
                        PROM_ACTION.labels(type='selfip', action='update').inc()

                # orphaned
                else:
                    orphaned.append(old_sip)
            except iControlUnexpectedHTTPError as e:
                LOG.exception(e)

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
            PROM_ACTION.labels(type='selfip', action='create').inc()
        return orphaned

    @retry(
        retry=retry_if_exception_type(iControlUnexpectedHTTPError),
        wait=wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=stop_after_attempt(RETRY_ATTEMPTS)
    )
    @REQUEST_TIME_SYNC_ROUTEDOMAINS.time()
    def _sync_routedomains(self, vlans):
        orphaned = []
        prefixed_nets = self._prefix(vlans, constants.PREFIX_NET)
        rds = self.mgmt.tm.net.route_domains
        for rd in rds.get_collection():
            try:
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
                        PROM_ACTION.labels(type='routedomain', action='update').inc()
                        rd.update()

                # orphaned
                else:
                    orphaned.append(rd)
            except iControlUnexpectedHTTPError as e:
                LOG.exception(e)

        # New ones
        for name, vlan in prefixed_nets.items():
            try:
                PROM_ACTION.labels(type='routedomain', action='create').inc()
                rds.route_domain.create(
                    name=name, partition='Common', id=vlan['tag'],
                    vlans=['/Common/{}{}'.format(constants.PREFIX_VLAN, vlan['tag'])])
            except iControlUnexpectedHTTPError:
                # Try deleting selfip first and let it resync next time
                try:
                    self.delete_object('selfip', name)
                except iControlUnexpectedHTTPError:
                    pass
        return orphaned

    @retry(
        retry=retry_if_exception_type(iControlUnexpectedHTTPError),
        wait=wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=stop_after_attempt(RETRY_ATTEMPTS)
    )
    @REQUEST_TIME_SYNC_ROUTES.time()
    def _sync_routes(self, selfips):
        orphaned = []
        # We only need one route per network, remove larger gateway IPs
        tmp = defaultdict(list)
        for val in selfips.values():
            tmp[val['network_id']].append(int(netaddr.IPAddress(val['gateway_ip'])))

        # use network key due to config sync of routes
        prefixed_networks = dict(('{}{}'.format(constants.PREFIX_NET, val['network_id']), val)
                                 for val in selfips.values()
                                 if int(netaddr.IPAddress(val['gateway_ip'])) == min(tmp[val['network_id']]))

        routes = self.mgmt.tm.net.routes
        for route in routes.get_collection():
            try:
                # Not managed by agent, cleanup also selfip-based routes
                if not (route.name.startswith(constants.PREFIX_SELFIP) or route.name.startswith(constants.PREFIX_NET)):
                    pass

                # Update
                elif route.name in prefixed_networks:
                    selfip = prefixed_networks.pop(route.name)
                    gateway = '{}%{}'.format(
                        selfip['gateway_ip'],
                        selfip['tag']
                    )
                    network = 'default%{}'.format(selfip['tag'])
                    if route.gw != gateway or route.network != network:
                        route.gw = gateway
                        route.network = network
                        PROM_ACTION.labels(type='route', action='update').inc()
                        route.update()

                # orphaned
                else:
                    orphaned.append(route)
            except iControlUnexpectedHTTPError as e:
                LOG.exception(e)

        # New ones
        for name, selfip in prefixed_networks.items():
            gateway = '{}%{}'.format(
                selfip['gateway_ip'],
                selfip['tag']
            )
            network = 'default%{}'.format(selfip['tag'])
            PROM_ACTION.labels(type='route', action='create').inc()
            routes.route.create(network=network, gw=gateway,
                name=name, partition='Common')

        return orphaned

    @retry(
        retry=retry_if_exception_type((Timeout, ConnectionError)),
        wait=wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=stop_after_attempt(RETRY_ATTEMPTS)
    )
    @REQUEST_TIME_SYNC_ALL.time()
    def sync_all(self, vlans, selfips):
        orphaned = {}
        try:
            LOG.debug("Syncing vlans %s", [vlan['tag'] for vlan in vlans.values()])
            orphaned['vlan'] = self._sync_vlans(vlans)
        except iControlUnexpectedHTTPError as e:
            LOG.exception(e)

        try:
            LOG.debug("Syncing routedomains %s", [vlan['tag'] for vlan in vlans.values()])
            orphaned['routedomain'] = self._sync_routedomains(vlans)
        except iControlUnexpectedHTTPError as e:
            LOG.exception(e)

        try:
            LOG.debug("Syncing selfips %s", [selfip['ip_address'] for selfip in selfips.values()])
            orphaned['selfip'] = self._sync_selfips(selfips)
        except iControlUnexpectedHTTPError as e:
            LOG.exception(e)

        try:
            LOG.debug("Syncing routes %s", [selfip['gateway_ip'] for selfip in selfips.values()])
            orphaned['route'] = self._sync_routes(selfips)
        except iControlUnexpectedHTTPError as e:
            LOG.exception(e)

        # Cleanup should happen in reverse order
        for object_type in ['route', 'selfip', 'routedomain', 'vlan']:
            if object_type in orphaned and len(orphaned[object_type]) > 0:
                LOG.info("Cleaning up orphaned %s: %s", object_type, [o.name for o in orphaned[object_type]])
                for o in orphaned[object_type]:
                    try:
                        PROM_ACTION.labels(type=object_type, action='delete').inc()
                        o.delete()
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
