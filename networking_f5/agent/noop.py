# Copyright 2020 SAP SE
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

from oslo_log import log as logging

from networking_f5.agent.f5_agent import F5Backend

LOG = logging.getLogger(__name__)


class F5NoOpDriver(F5Backend):
    """Base class for F5 backend communication."""

    def __init__(self, cfg, uri, device_mappings):
        super(F5NoOpDriver, self).__init__(cfg, uri, device_mappings)

    def sync_all(self, vlans, selfips):
        LOG.info("Called sync_all with vlans=%s selfips=%s",
                 vlans, selfips)

    def get_devices(self):
        LOG.info("Called get_devies")
        return []

    def get_mac(self):
        LOG.info("Called get_mac")
        return '12:34:56:78'

    def get_host(self):
        LOG.info("Called get_devies")
        return 'example.net'

    def plug_interface(self, network_segment, device):
        LOG.info("Called plug_interface with network_segment=%s device=%s",
                 network_segment, device)
