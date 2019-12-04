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

import oslo_messaging
from netaddr import IPNetwork
from oslo_log import log as logging

from networking_f5 import constants
from neutron_lib.plugins import directory

LOG = logging.getLogger(__name__)


class F5DORpcCallback(object):
    target = oslo_messaging.Target(version='1.0')

    def __init__(self, f5plugin):
        self.f5plugin = f5plugin
        super(F5DORpcCallback, self).__init__()

    @property
    def plugin(self):
        if not hasattr(self, '_plugin'):
            self._plugin = directory.get_plugin()
        return self._plugin

    def get_selfips_and_vlans(self, context, **kwargs):
        host = kwargs.get('host')
        LOG.debug('get_selfips_and_vlans from %s', host)

        # Fetch all Self-IPs for this agent
        filters = {'device_owner': [constants.DEVICE_OWNER_SELFIP],
                   'binding:host_id': [host]}
        query = self.plugin._get_ports_query(context, filters=filters)

        res = collections.defaultdict(dict)
        subnet_mapping = {}
        for port in query.all():
            tag = port.binding_levels[-1].segment.segmentation_id
            physical_network = port.binding_levels[-1].segment.physical_network
            subnet_mapping[port.fixed_ips[0].subnet_id] = port.id

            res['selfips'].update({
                port.id: {
                    'ip_address': port.fixed_ips[0].ip_address,
                    'network_id': port.network_id,
                    'tag': tag,
                    'mac': port.device_id}})
            res['vlans'].update({port.network_id: {
                'tag': tag,
                'physical_network': physical_network}})

        # Update correct cidr prefix
        filters = {'id': subnet_mapping.keys()}
        subnets = self.plugin.get_subnets(
            context, filters, fields=['cidr', 'id'])
        for subnet in subnets:
            prefixlen = IPNetwork(subnet['cidr']).prefixlen
            port_id = subnet_mapping[subnet['id']]
            res['selfips'][port_id].update({'prefixlen': prefixlen})

        # Update correct MTU values
        filters = {'id': res['vlans'].keys()}
        networks = self.plugin.get_networks(
            context, filters, fields=['mtu', 'id'])
        for network in networks:
            res['vlans'][network['id']].update({'mtu': network['mtu']})

        return res

    def ensure_selfips_for_agent(self, context, **kwargs):
        host = kwargs.get('host')
        LOG.debug('ensure_selfips_for_agent from %s', host)

        # Fetch all listener ports for this host
        filters = {'device_owner': [constants.DEVICE_OWNER_LISTENER],
                   'binding:host_id': [host]}
        ports = self.plugin.get_ports(context, filters)

        class ListenerContext(object):
            def __init__(self, port, plugin, plugin_context, host):
                self.current = port
                self.host = host
                self._plugin = plugin
                self._plugin_context = plugin_context

            def host_agents(self, agent_type):
                return self._plugin.get_agents(
                    self._plugin_context,
                    filters={'agent_type': [agent_type],
                             'host': [self.host]})

        for listener in ports:
            self.f5plugin._ensure_selfips(
                ListenerContext(listener, self.plugin, context, host)
            )
