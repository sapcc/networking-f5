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

import abc
import sys
import time

import eventlet
import oslo_messaging
import six
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall
from prometheus_client import start_http_server, Counter
from stevedore import driver

from networking_f5 import constants
from networking_f5._i18n import _
from networking_f5.agent.vcmp import F5vCMPBackend
from neutron.agent import rpc as agent_rpc
from neutron.common import config as common_config
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.conf.agent import common as agent_config
from neutron_lib import constants as n_const
from neutron_lib import context
from neutron_lib.utils import helpers

# oslo_messaging/notify/listener.py documents that monkeypatching is required
eventlet.monkey_patch()

FULL_SYNC_EXCEPTIONS = Counter('networking_f5_full_sync_exceptions', 'Full Sync exception count')
FIVE_MINUTES = 5 * 60
LOG = logging.getLogger(__name__)
last_full_sync = .0

F5_OPTS = [
    cfg.StrOpt('backend',
               default='icontrol',
               choices=['do', 'icontrol', 'noop'],
               help=_('Backend driver for BigIP F5 communication')),
    cfg.FloatOpt('sync_interval', default=90,
                 help=_('Seconds between full sync.')),
    cfg.FloatOpt('cleanup_interval', default=600,
                 help=_('Seconds between selfip cleanups.')),
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
               deprecated_for_removal=True,
               help=_('Username for vCMP Host.')),
    cfg.StrOpt('password',
               secret=True,
               deprecated_for_removal=True,
               help=_('Password for vCMP Host')),
    cfg.ListOpt('devices',
                item_type=cfg.types.URI(schemes=['http', 'https']),
                default=[],
                help=_("List of device urls to be synced by the agent")),
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
    def sync_all(self, vlans, selfips, rds_in_use):
        """Sync all selfips and vlans to F5 L2"""

    @abc.abstractmethod
    def rd_in_use(self):
        """Get all RDs in use"""

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


class F5PluginAPI(object):
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


class F5AgentRpcCallBack(object):
    target = oslo_messaging.Target(version='1.4')

    def __init__(self, agent):
        self.agent = agent

    def security_groups_rule_updated(self, context, **kwargs):
        pass

    def security_groups_member_updated(self, context, **kwargs):
        pass

    def add_network(self, network_id, network_segment):
        pass

    def network_update(self, context, **kwargs):
        pass

    def port_update(self, context, **kwargs):
        port = kwargs['port']
        if (port['device_owner'] == constants.DEVICE_OWNER_SELFIP and
                port['binding:host_id'] == self.agent.conf.host and
                port['status'] == 'DOWN'):
            LOG.debug("Got Port update for self ip %s", kwargs['port'])
            self.agent._full_sync()


class F5NeutronAgent(object):
    def __init__(self, device_mappings):
        self.device_mappings = device_mappings
        self.conf = cfg.CONF
        self.host = self.conf.host
        self.devices = []
        self.port_up_ids = []
        self.vcmps = []
        self.pool = eventlet.GreenPool()

        self._connect()
        self.agent_state = {
            'binary': constants.AGENT_BINARY,
            'host': cfg.CONF.host,
            'topic': n_const.L2_AGENT_TOPIC,
            'configurations': self.get_agent_configurations(),
            'agent_type': constants.AGENT_TYPE_F5,
            'start_flag': True}

        if self.conf.debug:
            # OSX workaround
            sys.setrecursionlimit(15000)

        self.setup_rpc()
        LOG.debug("Ensuring all selfips bound for this agent")
        self.agent_rpc.ensure_selfips_for_agent(self.context)

    def setup_rpc(self):
        self.context = context.get_admin_context_without_session()
        self.agent_id = '{}-{}'.format(constants.AGENT_BINARY, self.host)
        self.topic = topics.AGENT
        self.rpc_callback = F5AgentRpcCallBack(self)
        self.endpoints = [self.rpc_callback]
        self.agent_rpc = F5PluginAPI(constants.TOPIC, self.host)
        self.plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)

        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE]]
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers,
                                                     start_listening=False)

    def run(self):
        LOG.info('networking-f5-agent initialized, running...')
        if cfg.CONF.F5.prometheus:
            start_http_server(8000)
        self.connection.consume_in_threads()
        heartbeat = loopingcall.FixedIntervalLoopingCall(self._report_state)
        heartbeat.start(
            interval=self.conf.AGENT.report_interval,
            initial_delay=self.conf.AGENT.report_interval,
            stop_on_exception=False)
        cleanup = loopingcall.FixedIntervalLoopingCall(self._cleanup)
        cleanup.start(interval=self.conf.F5.cleanup_interval)
        sync_loop = loopingcall.FixedIntervalLoopingCall(self._full_sync)
        sync_loop.start(interval=self.conf.F5.sync_interval, stop_on_exception=False)
        sync_loop.wait()

    def _report_state(self):
        if 0 < last_full_sync < time.time() - FIVE_MINUTES:
            LOG.warning("Last sync loop outlasted for more than five minutes (%s), skipping report",
                        time.strftime("%c", time.localtime(last_full_sync)))
            return

        try:
            # Sync-Loop completed, report state
            devices = len(self.get_all_devices())
            self.agent_state.get('configurations')['devices'] = devices
            self.state_rpc.report_state(self.context,
                                        self.agent_state,
                                        True)
        except Exception:
            LOG.exception("Failed reporting state!")

    def _connect(self):
        self.devices = [driver.DriverManager(
            namespace='neutron.ml2.f5.backend_drivers',
            name=self.conf.F5.backend,
            invoke_on_load=True,
            invoke_args=(self.conf, uri, self.device_mappings)
        ).driver for uri in sorted(self.conf.F5.devices)]
        self.vcmps = [F5vCMPBackend(uri, self.device_mappings)
                      for uri in sorted(self.conf.F5_VCMP.devices or
                                        self.conf.F5_VCMP.hosts_guest_mappings.keys())]
        # Re-patch backend drivers
        eventlet.monkey_patch()

    def get_all_devices(self):
        all_devices = set()
        for device in self.devices:
            all_devices.update(device.get_devices())
        return all_devices

    def get_agent_configurations(self):
        return {
            'device_mappings': self.device_mappings,
            'log_agent_heartbeats': self.conf.AGENT.log_agent_heartbeats,
            'device_hosts': {
                device.get_host(): device.get_mac() for device in self.devices
            },
        }

    @lockutils.synchronized('_f5_full_sync')
    @FULL_SYNC_EXCEPTIONS.count_exceptions()
    def _full_sync(self):
        res = self.agent_rpc.get_selfips_and_vlans(self.context)

        # Safeguard for RDs in use
        rds_in_use = set()
        for device in self.devices:
            rds_in_use.update(device.rd_in_use())

        for device in self.devices:
            LOG.debug("Syncing F5 device %s", device.get_host())
            self.pool.spawn_n(
                device.sync_all,
                vlans=res.get('vlans', {}).copy(),
                selfips={
                    key: val for key, val in res.get(
                        'selfips',
                        {}).items() if
                    device.get_host() == val.get('host', None)
                },
                rds_in_use=rds_in_use
            )

        for vcmp in self.vcmps:
            LOG.debug("Syncing VCMP host %s", vcmp.vcmp_host)
            self.pool.spawn_n(vcmp.sync_vlan, res['vlans'].copy())

        global last_full_sync
        self.pool.waitall()
        last_full_sync = time.time()

        LOG.debug("Sync loop finished")
        port_up_ids = self.get_all_devices()
        if self.port_up_ids != port_up_ids:
            self.plugin_rpc.update_device_list(self.context, port_up_ids, [], self.agent_id, self.conf.host)
            self.port_up_ids = port_up_ids

    def _cleanup(self):
        LOG.debug("Running (dry-run=%s) cleanup for agent %s", not self.conf.F5.cleanup, self.host)
        self.agent_rpc.cleanup_selfips_for_agent(self.context, dry_run=not self.conf.F5.cleanup)


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

    agent = F5NeutronAgent(device_mappings)
    agent.run()
