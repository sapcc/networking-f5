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
import re

from netaddr import IPNetwork
from neutron_lib import constants as p_constants
from neutron_lib import rpc
from neutron_lib.agent import topics
from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import resources
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg
from oslo_log import log

from networking_f5 import constants
from networking_f5.plugins.ml2.drivers.mech_f5.rpc import F5DORpcCallback
from neutron import service
from neutron.db import db_base_plugin_v2
from neutron.db import provisioning_blocks
from neutron.plugins.ml2 import rpc as ml2_rpc
from neutron.plugins.ml2.drivers import mech_agent

LOG = log.getLogger(__name__)

CONF = cfg.CONF
CONF.register_opts([
    cfg.StrOpt('selfip_project_id',
               default='',
               help="(optional) keystone project name for self-ips")
], 'F5_DRIVER')


class F5MechanismDriver(mech_agent.SimpleAgentMechanismDriverBase,
                        db_base_plugin_v2.NeutronDbPluginV2):
    """Binds ports used by the F5 driver.
    """

    def __init__(self):
        super(F5MechanismDriver, self).__init__(
            constants.AGENT_TYPE_F5,
            constants.VIF_TYPE_F5,
            {portbindings.CAP_PORT_FILTER: False})
        self.notifier = ml2_rpc.AgentNotifierApi(topics.AGENT)
        LOG.info("F5 ML2 mechanism driver initialized...")

    def start_rpc_state_reports_listener(self):
        raise NotImplementedError()

    def start_rpc_listeners(self):
        conn = rpc.Connection()
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
        agents = context.host_agents(self.agent_type)
        if not agents:
            LOG.debug("Port %(pid)s on network %(network)s not bound, "
                      "no agent of type %(at)s registered on host %(host)s",
                      {'pid': context.current['id'],
                       'at': self.agent_type,
                       'network': context.network.current['id'],
                       'host': context.host})
        for agent in agents:
            for segment in context.segments_to_bind:
                if self.try_to_bind_segment_for_agent(context, segment,
                                                      agent):
                    LOG.debug("Bound using segment: %s", segment)
                    return

    @staticmethod
    def _make_selfip_dict(listener_port, device_id, description):
        fixed_ip = listener_port['fixed_ips'][0]
        return {
            'port': {
                'tenant_id': CONF.F5_DRIVER.selfip_project_id or listener_port['tenant_id'],
                'binding:host_id': listener_port['binding:host_id'],
                'name': 'local-{}-{}'.format(description, fixed_ip['subnet_id']),
                'network_id': listener_port['network_id'],
                'device_owner': constants.DEVICE_OWNER_SELFIP,
                'device_id': device_id,
                'description': description,
                'admin_state_up': True,
                'fixed_ips': [{'subnet_id': fixed_ip['subnet_id']}]
            }
        }

    def _ensure_selfips(self, context):
        """This function ensures that a listener ip has the right amount
           selfips for all devices and assigned correctly
        """
        plugin_context = context._plugin_context
        fixed_ip = context.current['fixed_ips'][0]

        agents = context.host_agents(constants.AGENT_TYPE_F5)
        if not agents:
            # rebind only if agents available
            return []

        filter = {'device_owner': [constants.DEVICE_OWNER_SELFIP,
                                   constants.DEVICE_OWNER_LEGACY],
                  'binding:host_id': [context.host],
                  'fixed_ips': {'subnet_id': [fixed_ip['subnet_id']]}}
        selfips = context._plugin.get_ports(plugin_context, filter)

        selfip_hosts = set()
        for selfip in list(selfips):
            if selfip['device_owner'] == constants.DEVICE_OWNER_SELFIP:
                # Modern selfip port
                selfip_hosts.add(selfip['description'])
            elif selfip['device_owner'] == constants.DEVICE_OWNER_LEGACY:
                # legacy selfip port
                m = re.match('local-(.*)-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
                             selfip.get('name', ''))
                if m:
                    selfip_hosts.add(m.group(1))
                else:
                    # Not a correct selfip, remove from original list
                    selfips.remove(selfip)

        # Create inital self-ips if missing for device
        f5_hosts = agents[0]['configurations'].get('device_hosts', {})
        for host in f5_hosts.keys():
            if host not in selfip_hosts:
                # Create SelfIP Port for device
                port_dict = self._make_selfip_dict(
                    context.current, fixed_ip['subnet_id'], host)
                selfips.append(
                    context._plugin.create_port(plugin_context, port_dict)
                )

        # Update allowed address pairs if needed
        subnet = self.get_subnet(plugin_context, fixed_ip['subnet_id'])
        allowed_address_pairs = [
            {'ip_address': "{}/{}".format(
                selfip['fixed_ips'][0]['ip_address'], IPNetwork(subnet['cidr']).prefixlen
            ), 'mac_address': f5_hosts.get(selfip['description'], '00:00:00:00:00:00')}
            for selfip in selfips
        ]
        if context.current['allowed_address_pairs'] != allowed_address_pairs:
            # update allowed_address_pairs with self-ips
            port_update = {'port': {'allowed_address_pairs': allowed_address_pairs}}
            context._plugin.update_address_pairs_on_port(plugin_context,
                                                         context.current['id'],
                                                         port_update,
                                                         context.current,
                                                         context.current)
        return selfips

    def update_port_postcommit(self, context):
        plugin_context = context._plugin_context

        # skip Self-IP, but notify agent
        if context.current['device_owner'] == constants.DEVICE_OWNER_SELFIP:
            self._notify_port_updated(context)
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

        selfips = self._ensure_selfips(context)
        LOG.debug("Created selfip ports %s for listener %s",
                  [selfip['id'] for selfip in selfips],
                  context.current['id'])

        self._notify_port_updated(context)
        provisioning_blocks.provisioning_complete(
            plugin_context, context.current['id'], resources.PORT,
            provisioning_blocks.L2_AGENT_ENTITY)
        context._plugin.update_port_status(plugin_context,
                                           context.current['id'],
                                           p_constants.PORT_STATUS_ACTIVE)

    def _notify_port_updated(self, mech_context):
        port = mech_context.current
        segment = mech_context.bottom_bound_segment
        if not segment:
            # REVISIT(rkukura): This should notify agent to unplug port
            network = mech_context.network.current
            LOG.debug("In _notify_port_updated(), no bound segment for "
                      "port %(port_id)s on network %(network_id)s",
                      {'port_id': port['id'], 'network_id': network['id']})
            return
        self.notifier.port_update(mech_context._plugin_context, port,
                                  segment[api.NETWORK_TYPE],
                                  segment[api.SEGMENTATION_ID],
                                  segment[api.PHYSICAL_NETWORK])

    def delete_port_postcommit(self, context):
        # Cleanup selfips if listener deleted
        if context.current['device_owner'] == constants.DEVICE_OWNER_LISTENER:
            plugin_context = context._plugin_context

            # Fetch all listeners of this subnet and device
            filters = {'device_owner': [constants.DEVICE_OWNER_LISTENER,
                                        constants.DEVICE_OWNER_LEGACY],
                       'fixed_ips': {'subnet_id': [context.current['fixed_ips'][0]['subnet_id']]},
                       'binding:host_id': [context.host]}

            subnet_listeners = [port['id'] for port in
                                context._plugin.get_ports(plugin_context, filters, fields=['id', 'name'])
                                if not (port.get('name', '').startswith('local-')
                                        or port['id'] == context.current['id'])]

            if not subnet_listeners:
                # No listener left, cleanup selfips
                filters = {'device_owner': [constants.DEVICE_OWNER_SELFIP,
                                            constants.DEVICE_OWNER_LEGACY],
                           'fixed_ips': {'subnet_id': [context.current['fixed_ips'][0]['subnet_id']]},
                           'binding:host_id': [context.host]}

                all_selfips = [selfip['id'] for selfip in
                               context._plugin.get_ports(plugin_context, filters, fields=['id', 'device_owner', 'name'])
                               if not ((selfip['device_owner'] == constants.DEVICE_OWNER_LEGACY)
                                       and selfip['name'].startswith('loadbalancer-'))]

                for selfip in all_selfips:
                    LOG.info('[delete_port_postcommit] Cleanup Self-IP of '
                             'listener %s: deleting %s', context.current['id'], selfip)
                    context._plugin.delete_port(plugin_context, selfip)
