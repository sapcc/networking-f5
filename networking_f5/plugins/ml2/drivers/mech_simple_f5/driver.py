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
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import context
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg
from oslo_log import log
import oslo_messaging

from networking_f5 import constants

LOG = log.getLogger(__name__)

CONF = cfg.CONF
CONF.register_opts([
    cfg.ListOpt('physical_networks',
                default=[],
                help="List of pyhsical networks the driver should use to"
                     "indentify the segment to use (if not specified"
                     "driver will use first segment in the list)"),
    cfg.ListOpt('supported_device_owners',
                default=[constants.DEVICE_OWNER_SELFIP,
                         constants.DEVICE_OWNER_LISTENER,
                         constants.DEVICE_OWNER_LEGACY],
                help="Override list of supported device owners")
], 'ml2_f5')
CONF.register_opts([
    cfg.StrOpt('driver',
               default='noop',
               help='The Drivers to handle sending notifications. '
                    'Possible values are messaging, messagingv2, '
                    'routing, log, test, noop'),
    cfg.StrOpt('transport_url',
               secret=True,
               help='A URL representing the messaging driver to use for '
                    'notifications. If not set, we fall back to the same '
                    'configuration used for RPC.'),
    cfg.ListOpt('topics',
                default=['notifications', ],
                help='AMQP topic used for OpenStack notifications.'),
    cfg.IntOpt('retry', default=-1,
               help='The maximum number of attempts to re-send a notification '
                    'message which failed to be delivered due to a '
                    'recoverable error. 0 - No retry, -1 - indefinite'),
], 'ml2_f5_notifications')


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
        self.supported_vnic_types = [portbindings.VNIC_NORMAL,
                                     portbindings.VNIC_BAREMETAL]
        self.supported_device_owners = CONF.ml2_f5.supported_device_owners
        self.physical_networks = CONF.ml2_f5.physical_networks
        self.notification_transport = oslo_messaging.get_notification_transport(
            CONF, url=CONF.ml2_f5_notifications.transport_url)
        self.notifier = None
        LOG.info("F5 Simple ML2 mechanism driver initialized for device-owners: %s",
                 self.supported_device_owners)

    def _get_notifier(self):
        return oslo_messaging.Notifier(
            transport=self.notification_transport,
            driver=CONF.ml2_f5_notifications.driver,
            topics=CONF.ml2_f5_notifications.topics,
            retry=CONF.ml2_f5_notifications.retry,
            publisher_id=f"networking_f5.{CONF.host}")

    def _notify(self, security_group_id, action):
        cxt = context.get_admin_context()
        if CONF.ml2_f5_notifications.driver == 'noop':
            return
        LOG.debug("Networking F5 mechanism driver sending notification about "
                  f"{action} Security Group {security_group_id}")
        self.notifier.info(cxt, f'security_group.{action}',
                           {'security_group_id': security_group_id})

    def initialize(self):
        self.notifier = self._get_notifier()
        registry.subscribe(self._process_security_group_after_delete,
                           resources.SECURITY_GROUP,
                           events.AFTER_DELETE)
        registry.subscribe(self._process_security_group_rule_after_create,
                           resources.SECURITY_GROUP_RULE,
                           events.AFTER_CREATE)
        registry.subscribe(self._process_security_group_rule_after_delete,
                           resources.SECURITY_GROUP_RULE,
                           events.AFTER_DELETE)
        LOG.info("Networking F5 mechanism driver initialized")

    def _process_security_group_after_delete(
            self, resource, event, trigger, payload):
        self._notify(payload.resource_id, 'deleted')

    def _process_security_group_rule_after_create(
            self, resource, event, trigger, payload):
        self._notify(payload.latest_state['security_group_id'], 'updated')

    def _process_security_group_rule_after_delete(
            self, resource, event, trigger, payload):
        self._notify(payload.metadata['security_group_id'], 'updated')

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

