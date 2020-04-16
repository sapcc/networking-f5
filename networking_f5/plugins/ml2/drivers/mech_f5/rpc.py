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
import re
import oslo_messaging
from netaddr import IPNetwork
from neutron_lib.plugins import directory
from oslo_log import log as logging

from networking_f5 import constants

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
        host = kwargs.pop('host')
        LOG.debug('get_selfips_and_vlans from %s', host)

        # Fetch all Self-IPs for this agent
        filters = {'device_owner': [constants.DEVICE_OWNER_SELFIP,
                                    constants.DEVICE_OWNER_LEGACY],
                   'binding:host_id': [host]}
        query = self.plugin._get_ports_query(context, filters=filters)

        res = collections.defaultdict(dict)
        subnet_mapping = collections.defaultdict(list)
        for port in query.all():
            device = port.description

            if port.device_owner == constants.DEVICE_OWNER_LEGACY:
                # Skip legacy VIP ports
                m = re.match('local-(.*)-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
                             port.name)
                if not m:
                    continue
                device = m.group(1)

            if not port.binding_levels:
                LOG.warning("No bindings for port %s (network %s) found, "
                            "cannot configure F5 layer2 access.",
                            port.network_id, port.id)
                continue

            # Use vlan segments associated with exactly this port
            segment = [binding_level.segment for binding_level in port.binding_levels
                       if binding_level.segment.network_type == 'vlan' and binding_level.port_id == port.id]
            if not segment:
                LOG.error("No valid binding level found for port %s", port.id)
                continue

            tag = segment[0].segmentation_id
            # expect level 1 to be the correct physical network
            physical_network = segment[0].physical_network

            subnet_mapping[port.fixed_ips[0].subnet_id].append(port.id)

            res['selfips'].update({
                port.id: {
                    'ip_address': port.fixed_ips[0].ip_address,
                    'network_id': port.network_id,
                    'tag': tag,
                    'host': device}})
            res['vlans'].update({port.network_id: {
                'tag': tag,
                'physical_network': physical_network}})

        # Freeze defaultdict
        subnet_mapping.default_factory = None

        # Update correct cidr prefix
        filters = {'id': list(subnet_mapping.keys())}
        subnets = self.plugin.get_subnets(
            context, filters, fields=['cidr', 'id', 'gateway_ip'])
        for subnet in subnets:
            network = IPNetwork(subnet['cidr'])
            for port_id in subnet_mapping[subnet['id']]:
                res['selfips'][port_id].update({
                    'network': str(network.network),
                    'prefixlen': network.prefixlen,
                    'gateway_ip': subnet['gateway_ip']
                })

        # Update correct MTU values
        filters = {'id': list(res['vlans'].keys())}
        networks = self.plugin.get_networks(
            context, filters, fields=['mtu', 'id'])
        for network in networks:
            res['vlans'][network['id']].update({'mtu': network['mtu']})

        return res

    def ensure_selfips_for_agent(self, context, **kwargs):
        host = kwargs.get('host')
        LOG.debug('ensure_selfips_for_agent from %s', host)

        # Fetch all listener ports for this host
        filters = {'device_owner': [constants.DEVICE_OWNER_LISTENER,
                                    constants.DEVICE_OWNER_LEGACY],
                   'binding:host_id': [host]}
        ports = self.plugin.get_ports(context, filters)

        class ListenerContext(object):
            def __init__(self, port, plugin, plugin_context, _host):
                self.current = port
                self.host = _host
                self._plugin = plugin
                self._plugin_context = plugin_context

            def host_agents(self, agent_type):
                return self._plugin.get_agents(
                    self._plugin_context,
                    filters={'agent_type': [agent_type],
                             'host': [self.host]})

        for listener in ports:
            if listener['device_owner'] == constants.DEVICE_OWNER_LEGACY:
                # Skip legacy SelfIP ports, we're looking for VIP ports
                if not listener.get('name', '').startswith('loadbalancer-'):
                    continue

            self.f5plugin._ensure_selfips(
                ListenerContext(listener, self.plugin, context, host)
            )

    def cleanup_selfips_for_agent(self, context, **kwargs):
        host = kwargs.get('host')
        dry_run = kwargs.get('dry_run', True)
        LOG.info('cleanup_selfips_for_agent (dry_run=%s) from %s', dry_run, host)

        # Fetch all selfip ports for this host
        filters = {'device_owner': [constants.DEVICE_OWNER_SELFIP,
                                    constants.DEVICE_OWNER_LEGACY],
                   'binding:host_id': [host]}

        # special handling for legacy selfips
        all_selfips = [selfip for selfip
                       in self.plugin.get_ports(context, filters, fields=['id', 'device_owner', 'fixed_ips', 'name'])
                       if not ((selfip['device_owner'] == constants.DEVICE_OWNER_LEGACY)
                               and selfip['name'].startswith('loadbalancer-'))]

        # try find listener of the selfips
        filters = {'device_owner': [constants.DEVICE_OWNER_LISTENER,
                                    constants.DEVICE_OWNER_LEGACY],
                   'binding:host_id': [host],
                   'fixed_ips': {'subnet_id': [selfip['fixed_ips'][0]['subnet_id'] for selfip in all_selfips]}}
        listener_subnets = set([port['fixed_ips'][0]['subnet_id'] for port in
                            self.plugin.get_ports(context, filters, fields=['fixed_ips', 'name'])
                            if not port.get('name', '').startswith('local-')])

        for selfip in all_selfips:
            if selfip['fixed_ips'][0]['subnet_id'] not in listener_subnets:
                LOG.info('Found orphaned selfip for %s: deleting %s', host, selfip['id'])
                if not dry_run:
                    self.plugin.delete_port(context, selfip['id'])
