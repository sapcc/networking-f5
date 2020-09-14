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

from neutron_lib.utils import helpers
from neutron_lib import context
from neutron.plugins.ml2.drivers.agent import _common_agent as ca
from neutron.plugins.ml2.drivers.agent import _agent_manager_base as amb
from neutron.conf.agent import common as agent_config
from neutron.common import topics
from neutron.common import rpc as n_rpc
from neutron.common import config as common_config
from networking_f5.agent.vcmp import F5vCMPBackend
from networking_f5._i18n import _
from networking_f5 import constants
from stevedore import driver
from prometheus_client import start_http_server
from oslo_service import service, loopingcall
from oslo_log import log as logging
from oslo_config import cfg
import six
import oslo_messaging
import abc
import sys

import eventlet

# oslo_messaging/notify/listener.py documents that monkeypatching is required
eventlet.monkey_patch()

LOG = logging.getLogger(__name__)

F5_OPTS = [
    cfg.StrOpt('backend',
               default='icontrol',
               choices=['do', 'icontrol', 'noop'],
               help=_('Backend driver for BigIP F5 communication')),
    cfg.FloatOpt('sync_interval', default=90,
                 help=_('Seconds between full sync.')),
    cfg.ListOpt('physical_device_mappings',
                default=[],
                help=_("List of <physical_network>:<device_interface>.")),
    cfg.ListOpt('devices',
                item_type=cfg.types.URI(schemes=['http', 'https']),
                default=[],
                help=_("List of device urls to be synced by the agent")),
    cfg.BoolOpt('https_verify',
                default=False,
                help=_("Verify https endpoint")),
    cfg.BoolOpt('prometheus',
                default=True,
                help=_("Enable prometheus metrics exporter")),
    cfg.BoolOpt('migration',
                default=False,
                help=_("Enable migration mode (disable syncing active devices)")),
    cfg.BoolOpt('cleanup',
                default=False,
                help=_("Enable automatic cleanup of selfips (else dry-run)")),
    cfg.BoolOpt('hardware_syncookie',
                default=True,
                help=_("Enables hardware syncookie mode on a VLAN. When enabled, "
                       "the hardware per-VLAN SYN cookie protection will be triggered "
                       "when the certain traffic threshold is reached on supported platforms.")),
    cfg.IntOpt('syn_flood_rate_limit',
                default=2000,
                help=_("Specifies the max number of SYN flood packets per second received on the "
                       "VLAN before the hardware per-VLAN SYN cookie protection is triggered.")),
    cfg.IntOpt('syncache_threshold',
                default=32000,
                help=_("Specifies the number of outstanding SYN packets on the VLAN that will "
                       "trigger the hardware per-VLAN SYN cookie protection.")),
    cfg.StrOpt('override_hostname',
               default=None,
               help=_('Override hostname')),
]

F5_VMCP_OPTS = [
    cfg.StrOpt('username',
               help=_('Username for vCMP Host.')),
    cfg.StrOpt('password',
               secret=True,
               help=_('Password for vCMP Host')),
    cfg.DictOpt('hosts_guest_mappings',
                default={},
                help=_("VCMP host and respective guest name mapping for "
                       "assigning VLANs, consisting of a list "
                       "of <host>:<guest_name>."),
                )
]


def list_opts():
    return [('agent', agent_config.AGENT_STATE_OPTS)]


def register_f5_opts(conf):
    conf.register_opts(F5_OPTS, 'F5')
    conf.register_opts(F5_VMCP_OPTS, 'F5_VCMP')


@six.add_metaclass(abc.ABCMeta)
class F5Backend(object):
    """Base class for F5 backend communication."""

    @abc.abstractmethod
    def __init__(self, cfg, uri, device_mappings):
        """Constructor."""

    @abc.abstractmethod
    def sync_all(self, vlans, selfips):
        """Sync all selfips and vlans to F5 L2"""

    @abc.abstractmethod
    def get_devices(self):
        """Fetch all devices (selfip ports)"""

    @abc.abstractmethod
    def get_mac(self):
        """return device mac"""

    @abc.abstractmethod
    def get_host(self):
        """return device host"""

    @abc.abstractmethod
    def is_active(self):
        """return if device is active"""

    @abc.abstractmethod
    def plug_interface(self, network_segment, device):
        """plug interface"""


class F5DOPluginAPI(object):
    """F5 declarative onboarding agent RPC callback
       in plugin implementations.
    """

    def __init__(self, topic, host):
        self.host = host
        target = oslo_messaging.Target(
            topic=topic,
            version='1.0')
        self.client = n_rpc.get_client(target)

    def get_selfips_and_vlans(self, context, **kwargs):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_selfips_and_vlans',
                          host=self.host, **kwargs)

    def ensure_selfips_for_agent(self, context, **kwargs):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'ensure_selfips_for_agent',
                          host=self.host, **kwargs)

    def cleanup_selfips_for_agent(self, context, **kwargs):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'cleanup_selfips_for_agent',
                          host=self.host, **kwargs)


class F5DOAgentManagerRpcCallBackBase(amb.CommonAgentManagerRpcCallBackBase):
    target = oslo_messaging.Target(version='1.4')

    def security_groups_rule_updated(self, context, **kwargs):
        pass

    def security_groups_member_updated(self, context, **kwargs):
        pass

    def add_network(self, network_id, network_segment):
        self.network_map[network_id] = network_segment

    def network_update(self, context, **kwargs):
        network_id = kwargs['network']['id']
        for port_data in self.agent.network_ports[network_id]:
            self.updated_devices.add(port_data['device'])

    def port_update(self, context, **kwargs):
        port = kwargs['port']
        self.updated_devices.add(port['mac_address'])


class F5Manager(amb.CommonAgentManagerBase):
    def __init__(self, device_mappings):
        super(F5Manager, self).__init__()
        self.device_mappings = device_mappings
        self.rpc = None
        self.conf = cfg.CONF
        self.host = self.conf.host
        self.plugin_rpc = F5DOPluginAPI(constants.TOPIC, self.host)
        self.ctx = context.get_admin_context_without_session()
        self.devices = []
        self.vcmps = []
        self._connect()

        LOG.debug("Ensuring all selfips bound for this agent")
        self.plugin_rpc.ensure_selfips_for_agent(self.ctx)

        sync_interval = self.conf.F5.sync_interval
        if sync_interval:
            self.fullsync = loopingcall.FixedIntervalLoopingCall(
                self._full_sync)
            self.fullsync.start(
                interval=sync_interval,
                stop_on_exception=False)

        self.cleanup = loopingcall.FixedIntervalLoopingCall(
            self.plugin_rpc.cleanup_selfips_for_agent, self.ctx,
            dry_run=not self.conf.F5.cleanup)
        self.cleanup.start(
            interval=600,
            stop_on_exception=False)

    def _connect(self):
        self.devices = [driver.DriverManager(
            namespace='neutron.ml2.f5.backend_drivers',
            name=self.conf.F5.backend,
            invoke_on_load=True,
            invoke_args=(self.conf, uri, self.device_mappings)
        ).driver for uri in sorted(self.conf.F5.devices)]
        if self.conf.F5_VCMP.hosts_guest_mappings:
            self.vcmps = [F5vCMPBackend(
                self.device_mappings,
                self.conf.F5_VCMP.username,
                self.conf.F5_VCMP.password,
                host,
                guest
            ) for host, guest in
                self.conf.F5_VCMP.hosts_guest_mappings.items()]

    def get_all_devices(self):
        all_devices = set()
        for device in self.devices:
            all_devices.update(device.get_devices())
        return all_devices

    def get_devices_modified_timestamps(self, devices):
        return dict()

    def get_agent_configurations(self):
        return {
            'device_mappings': self.device_mappings,
            'log_agent_heartbeats': self.conf.AGENT.log_agent_heartbeats,
            'device_hosts': {
                device.get_host(): device.get_mac() for device in self.devices
            },
        }

    def get_agent_id(self):
        return '{}-{}'.format(constants.AGENT_BINARY, self.host)

    def get_rpc_callbacks(self, context, agent, sg_agent):
        return F5DOAgentManagerRpcCallBackBase(
            context, agent, sg_agent)

    def get_rpc_consumers(self):
        return [[topics.PORT, topics.UPDATE],
                [topics.NETWORK, topics.UPDATE]]

    def _full_sync(self):
        res = self.plugin_rpc.get_selfips_and_vlans(self.ctx)

        for device in self.devices:
            if cfg.CONF.F5.migration and device.is_active():
                LOG.warning("Migration: Skipping active F5 device %s", device.get_host())
                continue

            LOG.debug("Syncing F5 device %s", device.get_host())
            device.sync_all(
                vlans=res.get('vlans', {}).copy(),
                selfips={
                    key: val for key, val in res.get(
                        'selfips',
                        {}).items() if
                    device.get_host() == val.get('host', None)
                })

        for vcmp in self.vcmps:
            if cfg.CONF.F5.migration:
                active_devices = [device.device.hostname for device in self.devices
                                  if device.is_active()]
                if vcmp.vcmp_guest in active_devices:
                    LOG.warning("Migration: Skipping active F5 device %s", vcmp.vcmp_host)
                    continue
            LOG.debug("Syncing VCMP host %s", vcmp.vcmp_host)
            vcmp.sync_vlan(res['vlans'].copy())

    def ensure_port_admin_state(self, device, admin_state_up):
        pass

    def get_extension_driver_type(self):
        pass

    def get_agent_api(self, **kwargs):
        pass

    def _interface_plugged(self, network_segment, device):
        return any([host.plug_interface(network_segment, device)
                    for host in self.devices])

    def plug_interface(
            self,
            network_id,
            network_segment,
            device,
            device_owner):
        LOG.debug("PLUG_INTERFACE: {}".format(device))
        if not self._interface_plugged(network_segment, device):
            self._full_sync()

        return self._interface_plugged(network_segment, device)

    def setup_arp_spoofing_protection(self, device, device_details):
        pass

    def delete_arp_spoofing_protection(self, devices):
        pass

    def delete_unreferenced_arp_protection(self, current_devices):
        pass


def main():
    register_f5_opts(cfg.CONF)
    agent_config.register_agent_state_opts_helper(cfg.CONF)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()

    try:
        device_mappings = helpers.parse_mappings(
            cfg.CONF.F5.physical_device_mappings)
    except ValueError as e:
        LOG.error("Parsing physical_device_mappings failed: %s. "
                  "Agent terminated!", e)
        sys.exit(1)
    LOG.info("Device mappings: %s", device_mappings)

    polling_interval = cfg.CONF.AGENT.polling_interval
    quitting_rpc_timeout = cfg.CONF.AGENT.quitting_rpc_timeout
    f5manager = F5Manager(device_mappings)
    agent = ca.CommonAgentLoop(f5manager,
                               polling_interval,
                               quitting_rpc_timeout,
                               constants.AGENT_TYPE_F5,
                               constants.AGENT_BINARY)

    LOG.info('networking-f5-agent initialized, starting up...')
    if cfg.CONF.F5.prometheus:
        start_http_server(8000)
    service.launch(cfg.CONF, agent, restart_method='mutate').wait()
