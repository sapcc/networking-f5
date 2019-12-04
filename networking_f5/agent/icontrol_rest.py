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

from f5.bigip import ManagementRoot
from icontrol.exceptions import iControlUnexpectedHTTPError
from neutron_lib.utils import helpers
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


class F5iControlRestBackend(F5Backend):
    def __init__(self, cfg, uri, device_mappings):
        super(F5iControlRestBackend, self).__init__(cfg, uri, device_mappings)
        self.conf = cfg
        self.device = parse.urlparse(uri)
        self.devices = []  # SelfIP Ports
        self.device_mappings = device_mappings
        self.mgmt = None

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

    REQUEST_TIME_SYNC_VLANS = Summary(
        'sync_vlan_seconds',
        'Time spent processing vlans')

    @REQUEST_TIME_SYNC_VLANS.time()
    def _sync_vlans(self, vlans):
        new_vlans = {
            constants.PREFIX_VLAN +
            name: val for name,
            val in vlans.items()}
        v = self.mgmt.tm.net.vlans
        for old_vlan in v.get_collection():
            # Not managed by agent
            if not old_vlan.name.startswith(constants.PREFIX_VLAN):
                pass

            # Update
            elif old_vlan.name in new_vlans:
                vlan = new_vlans.pop(old_vlan.name)
                if old_vlan.tag != vlan['tag'] or old_vlan.mtu != vlan['mtu']:
                    old_vlan.tag = vlan['tag']
                    old_vlan.mtu = vlan['mtu']
                    old_vlan.update()
                    self.vlan_update.inc()

            # orphaned
            else:
                try:
                    old_vlan.delete()
                    self.vlan_delete.inc()
                except iControlUnexpectedHTTPError:
                    pass

        # New ones
        for name, vlan in new_vlans.items():
            v.vlan.create(name=name, partition='Common',
                          tag=vlan['tag'], mtu=vlan['mtu'])
            self.vlan_create.inc()

    REQUEST_TIME_SYNC_SELFIPS = Summary(
        'sync_selfip_seconds',
        'Time spent processing selfips')

    @REQUEST_TIME_SYNC_SELFIPS.time()
    def _sync_selfips(self, selfips):
        sips = self.mgmt.tm.net.selfips.get_collection()
        self.devices = [sip.name[len(constants.PREFIX_SELFIP):] for sip in sips
                        if sip.name.startswith(constants.PREFIX_SELFIP)]
        for old_sip in sips:
            # Not managed by agent
            if not old_sip.name.startswith(constants.PREFIX_SELFIP):
                continue

            # Update
            elif old_sip.name in selfips:
                selfip = selfips.pop(old_sip.name)
                if old_sip.vlan != '/Common/{}'.format(
                        selfip['network_id']
                ) or old_sip.address != selfip['ip_address']:
                    old_sip.vlan = '/Common/{}'.format(
                        constants.PREFIX_VLAN + selfip['network_id'])
                    old_sip.address = '%s%%%d'.format(
                        selfip['ip_address'], selfip['tag'])
                    old_sip.update()
                    self.selfip_update.inc()

            # orphaned
            else:
                old_sip.delete()
                self.selfip_delete.inc()

        # New ones
        for name, selfip in selfips.items():
            if self.mac != selfip['mac']:
                continue

            self.mgmt.tm.net.selfips.selfip.create(
                name=constants.PREFIX_SELFIP + name,
                partition='Common',
                vlan=constants.PREFIX_VLAN + selfip['network_id'],
                address='{}%{}/{}'.format(
                    selfip['ip_address'],
                    selfip['tag'],
                    selfip['prefixlen']
                ),
            )
            self.selfip_create.inc()

    REQUEST_TIME_SYNC_ROUTEDOMAINS = Summary(
        'sync_routedomains_seconds',
        'Time spent processing routedomains')

    @REQUEST_TIME_SYNC_ROUTEDOMAINS.time()
    def _sync_routedomains(self, vlans):
        prefixed_vlans = {
            constants.PREFIX_VLAN +
            name: val for name,
            val in vlans.items()}
        rds = self.mgmt.tm.net.route_domains
        for rd in rds.get_collection():
            # Not managed by agent
            if not rd.name.startswith(constants.PREFIX_VLAN):
                pass

            # Update
            elif rd.name in prefixed_vlans:
                # TODO
                vlan = prefixed_vlans.pop(rd.name)
                vlans = ['/Common/{}'.format(rd.name)]
                if rd.vlans != vlans or rd.id != vlan['tag']:
                    rd.vlans = vlans
                    rd.id = vlan['tag']
                    rd.update()
                    self.route_domain_update.inc()

            # orphaned
            else:
                try:
                    rd.delete()
                    self.route_domain_delete.inc()
                except iControlUnexpectedHTTPError:
                    pass

        # New ones
        for name, vlan in prefixed_vlans.items():
            try:
                rds.route_domain.create(
                    name=name, partition='Common', id=vlan['tag'],
                    vlans=['/Common/{}'.format(name)])
                self.route_domain_create.inc()
            except iControlUnexpectedHTTPError:
                # Try deleting selfip first and let it resync next time
                self.mgmt.tm.net.selfips.selfip.delete()

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
            self._sync_vlans(vlans)
        except iControlUnexpectedHTTPError as e:
            LOG.exception(e)

        try:
            self._sync_routedomains(vlans)
        except iControlUnexpectedHTTPError as e:
            LOG.exception(e)

        try:
            self._sync_selfips(selfips)
        except iControlUnexpectedHTTPError as e:
            LOG.exception(e)


    def plug_interface(self, network_segment, device):
        name = constants.PREFIX_SELFIP + device
        if self.mgmt.tm.net.selfips.selfip.exists(name=name):
            return True

        # wait till sync-loop processed the port
        return False

    GET_DEVICES_EXCEPTIONS = Counter(
        'get_devices_exceptions',
        'Exceptions during get_devices')

    @retry(
        retry=retry_if_exception_type((Timeout, ConnectionError)),
        wait=wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=stop_after_attempt(RETRY_ATTEMPTS)
    )
    @GET_DEVICES_EXCEPTIONS.count_exceptions()
    def get_devices(self):
        return self.devices
