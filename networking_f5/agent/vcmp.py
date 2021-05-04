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

import collections
import sys

import six
from f5.bigip import ManagementRoot
from icontrol.exceptions import iControlUnexpectedHTTPError
from oslo_config import cfg
from oslo_log import log as logging
from prometheus_client import Summary
from requests import Timeout, ConnectionError
from six.moves.urllib import parse
from tenacity import retry_if_exception_type, \
    wait_incrementing, stop_after_attempt, retry

from networking_f5 import constants

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

RETRY_ATTEMPTS = 3
RETRY_INITIAL_DELAY = 1
RETRY_BACKOFF = 5
RETRY_MAX = 3


class F5vCMPBackend(object):
    def __init__(self, uri, physical_device_mappings):
        self.mgmt = None
        self.mappings = physical_device_mappings
        self.device = parse.urlparse(uri)
        self.vcmp_username = self.device.username or CONF.F5_VCMP.username
        self.vcmp_password = parse.unquote(self.device.password or "") or CONF.F5_VCMP.password
        self.vcmp_host = self.device.hostname or self.device.path
        self.vcmp_guest = CONF.F5_VCMP.hosts_guest_mappings[self.vcmp_host]
        self._login()

    def _login(self):
        if not self.vcmp_username or not self.vcmp_password:
            LOG.error("Need to specifcy valid F5_VCMP.username and "
                      "F5_VCMP.vcmp_password configuration.")
            sys.exit(1)

        self.mgmt = ManagementRoot(
            self.vcmp_host,
            self.vcmp_username,
            self.vcmp_password,
            token=True
        )

    def _unregister_vlan(self, vlan):
        guest = self.mgmt.tm.vcmp.guests.guest.load(name=self.vcmp_guest)
        new_vlans = [six.text_type(mgmt_vlan) for mgmt_vlan in guest.vlans
                     if not mgmt_vlan.startswith('/Common/' + vlan.name)]
        guest.vlans = new_vlans
        guest.update()

    REQUEST_TIME_SYNC_VLAN = Summary(
        'sync_vcmp_vlans_seconds',
        'Time spent processing vcmp vlans')

    @retry(
        retry=retry_if_exception_type((Timeout, ConnectionError)),
        wait=wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=stop_after_attempt(RETRY_ATTEMPTS)
    )
    @REQUEST_TIME_SYNC_VLAN.time()
    def sync_vlan(self, vlans):
        v = self.mgmt.tm.net.vlans
        orig_vlans = {'{}{}'.format(constants.PREFIX_VLAN, val['tag']): val
                      for val in list(vlans.values())}
        for old_vlan in v.get_collection(requests_params={'params': {'expandSubcollections': 'true'}}):

            # Migration case
            if old_vlan.name.startswith('net-'):
                self._unregister_vlan(old_vlan)
                try:
                    old_vlan.delete()
                except iControlUnexpectedHTTPError:
                    pass
                continue

            # Not supposed to be managed by agent
            if not old_vlan.name.startswith(constants.PREFIX_VLAN):
                continue

            # Update
            if old_vlan.name in orig_vlans:
                vlan = orig_vlans.pop(old_vlan.name)
                if (old_vlan.tag != vlan['tag'] or old_vlan.mtu != vlan['mtu'] or
                        old_vlan.synFloodRateLimit != CONF.F5.syn_flood_rate_limit or
                        old_vlan.syncacheThreshold != CONF.F5.syncache_threshold):
                    old_vlan.tag = vlan['tag']
                    old_vlan.mtu = vlan['mtu']
                    old_vlan.hardwareSyncookie = 'enabled' if CONF.F5.hardware_syncookie else 'disabled'
                    old_vlan.synFloodRateLimit = CONF.F5.syn_flood_rate_limit
                    old_vlan.syncacheThreshold = CONF.F5.syncache_threshold
                    old_vlan.update()

                interface_names = [interface['name'] for interface in old_vlan.interfacesReference.get('items', [])]
                if self.mappings[vlan['physical_network']] not in interface_names:
                    old_vlan.interfaces_s.interfaces.create(
                        tagged=True,
                        name=self.mappings[vlan['physical_network']],
                        tagMode='service')

            # If unused, it's probably orphaned
            else:
                used = False
                for guest in self.mgmt.tm.vcmp.guests.get_collection():
                    if old_vlan.fullPath in guest.vlans:
                        used = True
                if not used:
                    try:
                        old_vlan.delete()
                    except iControlUnexpectedHTTPError:
                        pass

        # New ones
        for name, vlan in list(orig_vlans.items()):
            new_vlan = v.vlan.create(name=name,
                                     partition='Common',
                                     tag=vlan['tag'], mtu=vlan['mtu'],
                                     hardwareSyncookie='enabled' if CONF.F5.hardware_syncookie else 'disabled',
                                     synFloodRateLimit=CONF.F5.syn_flood_rate_limit,
                                     syncacheThreshold=CONF.F5.syncache_threshold)
            new_vlan.interfaces_s.interfaces.create(
                tagged=True,
                name=self.mappings[vlan['physical_network']],
                tagMode='service')

        # Assign VLANs to the correct guest, but keep mgmt networks
        try:
            guest = self.mgmt.tm.vcmp.guests.guest.load(name=self.vcmp_guest)
            expected = ['/Common/{}{}'.format(constants.PREFIX_VLAN, vlan['tag'])
                        for vlan in list(vlans.values())]
            expected.extend([six.text_type(mgmt_vlan)
                             for mgmt_vlan in guest.vlans
                             if not mgmt_vlan.startswith(
                             '/Common/' + constants.PREFIX_VLAN)])
            if collections.Counter(
                expected) != collections.Counter(guest.vlans):
                guest.vlans = expected
                guest.update()
        except iControlUnexpectedHTTPError as e:
            LOG.error("Failure configuring guest VLAN: %s", e)
