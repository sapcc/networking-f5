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

from neutron_lib import constants as p_constants
from neutron_lib.api.definitions import portbindings
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg
from oslo_log import log

from networking_f5 import constants

LOG = log.getLogger(__name__)

CONF = cfg.CONF
CONF.register_opts([
    cfg.ListOpt('physical_networks',
                default=[],
                help="List of pyhsical networks the driver should use to"
                     "indentify the segment to use (if not specified"
                     "driver will use first segment in the list)")
], 'ml2_f5')


class F5MechanismDriver(api.MechanismDriver):
    """ Simple driver that just binds ports created by the neutron-f5 network plugin
        from octavia.
    """

    def __init__(self):
        self.agent_type = constants.AGENT_TYPE_F5
        self.vif_type = constants.VIF_TYPE_F5
        self.vif_details = {
            portbindings.VIF_DETAILS_CONNECTIVITY: portbindings.CONNECTIVITY_L2,
            portbindings.CAP_PORT_FILTER: False}
        self.supported_vnic_types = [portbindings.VNIC_NORMAL]
        self.supported_device_owners = [constants.DEVICE_OWNER_SELFIP,
                                        constants.DEVICE_OWNER_LISTENER,
                                        constants.DEVICE_OWNER_LEGACY]
        self.physical_networks = CONF.ml2_f5.physical_networks
        LOG.info("F5 Simple ML2 mechanism driver initialized...")

    def initialize(self):
        pass

    def bind_port(self, context):
        LOG.debug("Attempting to bind port %(port)s on "
                  "network %(network)s",
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_NORMAL)
        if vnic_type not in self.supported_vnic_types:
            LOG.debug("Refusing to bind due to unsupported vnic_type: %s",
                      vnic_type)
            return
        device_owner = context.current.get('device_owner')
        if device_owner not in self.supported_device_owners:
            LOG.debug("Refusing to bind due to unsupported device_owner: %s",
                      device_owner)
            return
        for segment in context.segments_to_bind:
            if self.physical_networks:
                physnet = segment.get('physical_network')
                if physnet in self.physical_networks:
                    self._set_binding(context, segment)
                    return
            elif segment.get('network_type') == p_constants.TYPE_VLAN:
                self._set_binding(context, segment)
                return

    def _set_binding(self, context, segment):
        context.set_binding(segment[api.ID],
                            self.vif_type,
                            self.vif_details,
                            p_constants.ACTIVE)
