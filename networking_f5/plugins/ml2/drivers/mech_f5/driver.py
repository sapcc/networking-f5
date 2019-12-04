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

from netaddr import IPNetwork
from oslo_log import log

from networking_f5 import constants
from networking_f5.plugins.ml2.drivers.mech_f5.rpc import F5DORpcCallback
from neutron import service
from neutron.common import rpc
from neutron.db import db_base_plugin_v2
from neutron.db import provisioning_blocks
from neutron.plugins.ml2.drivers import mech_agent
from neutron_lib import constants as p_constants
from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import resources

LOG = log.getLogger(__name__)


class F5MechanismDriver(mech_agent.SimpleAgentMechanismDriverBase,
                        db_base_plugin_v2.NeutronDbPluginV2):
    """Binds ports used by the F5 driver.
    """

    def __init__(self):
        super(F5MechanismDriver, self).__init__(
            constants.AGENT_TYPE_F5,
            constants.VIF_TYPE_F5,
            {portbindings.CAP_PORT_FILTER: False})
        LOG.info("F5 ML2 mechanism driver initialized...")

    def start_rpc_state_reports_listener(self):
        raise NotImplementedError()

    def start_rpc_listeners(self):
        conn = rpc.create_connection()
        conn.create_consumer(constants.TOPIC,
                             [F5DORpcCallback(self)],
                             fanout=False)
        return conn.consume_in_threads()

    def get_workers(self):
        return [service.RpcWorker([self], worker_process_count=0)]

    def initialize(self):
        self.set_ipam_backend()
        pass

    def get_allowed_network_types(self, agent=None):
        return [p_constants.TYPE_VLAN]

    def get_mappings(self, agent):
        return agent['configurations'].get(
            'device_mappings', {})

    @staticmethod
    def _make_selfip_dict(listener_port, device_mac):
        fixed_ip = listener_port['fixed_ips'][0]
        return {
            'port': {
                'tenant_id': listener_port['tenant_id'],
                'binding:host_id': listener_port['binding:host_id'],
                'name': 'self-ip-{}'.format(fixed_ip['subnet_id']),
                'network_id': listener_port['network_id'],
                'device_owner': constants.DEVICE_OWNER_SELFIP,
                'device_id': device_mac,
                'admin_state_up': True,
                'fixed_ips': [{'subnet_id': fixed_ip['subnet_id']}]
            }
        }

    def _ensure_selfips(self, context):
        """ This function ensures that a listener ip has the right amount
            selfips for all devices and assigned correctly """
        plugin_context = context._plugin_context
        fixed_ip = context.current['fixed_ips'][0]

        agents = context.host_agents(constants.AGENT_TYPE_F5)
        mac_addresses = agents[0]['configurations'].get('device_macs', 0)

        filter = {'device_owner': [constants.DEVICE_OWNER_SELFIP],
                  'device_id': mac_addresses,
                  'binding:host_id': [context.host],
                  'fixed_ips': {'subnet_id': [fixed_ip['subnet_id']]}}
        selfips = context._plugin.get_ports(plugin_context, filter)

        # Create inital self-ips if missing for device
        for mac_address in mac_addresses:
            if mac_address not in [port['device_id'] for port in selfips]:
                # Create SelfIP Port for device
                port_dict = self._make_selfip_dict(
                    context.current, mac_address)
                selfips.append(
                    context._plugin.create_port(plugin_context, port_dict)
                )

        if len(context.current['allowed_address_pairs']) != len(mac_addresses):
            # update allowed_address_pairs with self-ips
            subnet = self.get_subnet(plugin_context, fixed_ip['subnet_id'])
            port_update = {
                'port': {
                    'allowed_address_pairs': [
                        {'ip_address': "{}/{}".format(
                            selfip['fixed_ips'][0]['ip_address'],
                            IPNetwork(subnet['cidr']).prefixlen
                        ), 'mac_address': selfip['device_id']}
                        for selfip in selfips
                    ]
                }
            }

            context._plugin.update_address_pairs_on_port(plugin_context,
                                                         context.current['id'],
                                                         port_update,
                                                         context.current,
                                                         context.current)

    def create_port_postcommit(self, context):
        plugin_context = context._plugin_context

        # skip Self-IP
        if context.current['device_owner'] == constants.DEVICE_OWNER_SELFIP:
            return

        # Only accept listener_ips
        if context.current['device_owner'] != constants.DEVICE_OWNER_LISTENER:
            LOG.debug("Port '{}' has not a valid owner description, "
                      "not managed by us."
                      .format(context.current['id']))
            return

        # Need at least one ip address assigned
        if len(context.current['fixed_ips']) < 1:
            raise Exception("Port '{}' has no valid subnets".format(
                context.current['id']
            ))

        # LB listener ports only support one single ip per port
        if len(context.current['fixed_ips']) > 1:
            raise Exception(
                "Port '{}' has too many subnets, "
                "driver only supports one ip/port".format(
                    context.current['id']))

        # look for a living agent before provisioning selfips
        agents = context.host_agents(constants.AGENT_TYPE_F5)
        if len(agents) != 1:
            LOG.warning(
                "Couldn't create selfips for port '%s' "
                "since agents hosted in '%s' not found, "
                "will be eventually picked up by reconsiliation loop",
                context.host,
                context.current['id'])
            return

        self._ensure_selfips(context)

        provisioning_blocks.provisioning_complete(
            plugin_context, context.current['id'], resources.PORT,
            provisioning_blocks.L2_AGENT_ENTITY)
        context._plugin.update_port_status(plugin_context,
                                           context.current['id'],
                                           p_constants.PORT_STATUS_ACTIVE)
