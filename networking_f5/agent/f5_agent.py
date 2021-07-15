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
import threading
import time

import oslo_messaging
import six
from futurist import ThreadPoolExecutor
from futurist import periodics
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import eventletutils
from prometheus_client import Counter, start_http_server
from stevedore import driver

from networking_f5 import config  # noqa
from networking_f5 import constants
from networking_f5.agent.vcmp import F5vCMPBackend
from neutron.agent import rpc as agent_rpc
from neutron.common import config as common_config
from neutron.conf.agent import common as agent_config
from neutron_lib import constants as n_const
from neutron_lib import context
from neutron_lib import rpc as n_rpc
from neutron_lib.agent import topics
from neutron_lib.utils import helpers

CONF = cfg.CONF
LOG = logging.getLogger(__name__)
FULL_SYNC_EXCEPTIONS = Counter('networking_f5_full_sync_exceptions', 'Full Sync exception count')
SYNC_ITERATIONS = Counter('networking_f5_sync_iteration', 'Sync iterations', ['type'])
FIVE_MINUTES = 5 * 60

last_full_sync = .0
CONF.import_group('F5', 'networking_f5.config')
CONF.import_group('F5_VCMP', 'networking_f5.config')
agent_config.register_agent_state_opts_helper(CONF)


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
        return cctxt.cast(context, 'ensure_selfips_for_agent',
                          host=self.host, **kwargs)

    def cleanup_selfips_for_agent(self, context, **kwargs):
        cctxt = self.client.prepare()
        return cctxt.cast(context, 'cleanup_selfips_for_agent',
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
        if (port['device_owner'] == constants.DEVICE_OWNER_LISTENER and
                port['binding:host_id'] == self.agent.conf.host and
                port['status'] == 'ACTIVE'):
            LOG.debug("Got Port update for VIP %s, ensuring selfips", kwargs['port'])
            self.agent.agent_rpc.ensure_selfips_for_agent(self.agent.context)
        elif (port['device_owner'] == constants.DEVICE_OWNER_SELFIP and
              port['binding:host_id'] == self.agent.conf.host and
              port['status'] == 'DOWN'):
            LOG.debug("Got Port update for self ip %s", kwargs['port'])
            self.agent._full_sync()


class F5NeutronAgent(object):
    common_config.init(sys.argv[1:])

    def __init__(self, device_mappings):
        self.device_mappings = device_mappings
        self.host = CONF.host
        self.devices = []
        self.port_up_ids = []
        self.vcmps = []

        self._connect()
        self.agent_state = {
            'binary': constants.AGENT_BINARY,
            'host': CONF.host,
            'topic': n_const.L2_AGENT_TOPIC,
            'configurations': self.get_agent_configurations(),
            'agent_type': constants.AGENT_TYPE_F5,
            'start_flag': True}

        if CONF.debug:
            # OSX workaround
            sys.setrecursionlimit(15000)

        self.setup_rpc()

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
        LOG.info('networking-f5-agent initialized, eventlet=%s, running...',
                 eventletutils.is_monkey_patched('thread'))

        if cfg.CONF.F5.prometheus:
            LOG.info('Exposing Prometheus metrics on port 8000')
            start_http_server(8000)
        self.connection.consume_in_threads()
        worker = periodics.PeriodicWorker(
            [(self._report_state, None, None),
             (self._cleanup, None, None),
             (self._ensure_selfips, None, None),
             (self._full_sync, None, None)]
        )
        t = threading.Thread(target=worker.start)
        t.daemon = True
        t.start()
        t.join()

    @periodics.periodic(CONF.AGENT.report_interval)
    def _report_state(self):
        if 0 < last_full_sync < time.time() - FIVE_MINUTES:
            LOG.warning("Last sync loop outlasted for more than five minutes"
                        " (%s), skipping report",
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
            name=CONF.F5.backend,
            invoke_on_load=True,
            invoke_args=(CONF, uri, self.device_mappings)
        ).driver for uri in sorted(CONF.F5.devices)]
        self.vcmps = [F5vCMPBackend(uri, self.device_mappings)
                      for uri in sorted(
                CONF.F5_VCMP.devices or
                CONF.F5_VCMP.hosts_guest_mappings.keys())]

    def get_all_devices(self):
        all_devices = set()
        for device in self.devices:
            all_devices.update(device.get_devices())
        return all_devices

    def get_agent_configurations(self):
        return {
            'device_mappings': self.device_mappings,
            'log_agent_heartbeats': CONF.AGENT.log_agent_heartbeats,
            'device_hosts': {
                device.get_host(): device.get_mac() for device in self.devices
            },
        }

    @periodics.periodic(CONF.F5.sync_interval, run_immediately=True)
    @lockutils.synchronized('_f5_full_sync')
    @FULL_SYNC_EXCEPTIONS.count_exceptions()
    def _full_sync(self):
        res = self.agent_rpc.get_selfips_and_vlans(self.context)

        # Safeguard for RDs in use
        rds_in_use = set()
        for device in self.devices:
            rds_in_use.update(device.rd_in_use())
        with ThreadPoolExecutor(max_workers=4) as executer:
            for device in self.devices:
                LOG.debug("Syncing F5 device %s", device.get_host())
                executer.submit(
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
                executer.submit(vcmp.sync_vlan, res['vlans'].copy())

        global last_full_sync
        last_full_sync = time.time()

        LOG.debug("Sync loop finished")
        SYNC_ITERATIONS.labels('full_sync').inc()
        port_up_ids = self.get_all_devices()
        if self.port_up_ids != port_up_ids:
            self.plugin_rpc.update_device_list(self.context, port_up_ids, [],
                                               self.agent_id, CONF.host)
            self.port_up_ids = port_up_ids

    @periodics.periodic(CONF.F5.cleanup_interval, run_immediately=True)
    def _cleanup(self):
        LOG.debug("Running (dry-run=%s) cleanup for agent %s",
                  not CONF.F5.cleanup, self.host)
        self.agent_rpc.cleanup_selfips_for_agent(
            self.context, dry_run=not CONF.F5.cleanup)
        SYNC_ITERATIONS.labels('cleanup').inc()

    @periodics.periodic(CONF.F5.selfip_interval, run_immediately=True)
    def _ensure_selfips(self):
        LOG.debug("Running ensure_selfips for agent %s", self.host)
        self.agent_rpc.ensure_selfips_for_agent(self.context)
        SYNC_ITERATIONS.labels('ensure_selfips').inc()


def main():
    common_config.init(sys.argv[1:])
    common_config.setup_logging()

    try:
        device_mappings = helpers.parse_mappings(
            CONF.F5.physical_device_mappings)
    except ValueError as e:
        LOG.error("Parsing physical_device_mappings failed: %s. "
                  "Agent terminated!", e)
        sys.exit(1)
    LOG.info("Device mappings: %s", device_mappings)

    agent = F5NeutronAgent(device_mappings)
    agent.run()
