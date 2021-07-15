# Copyright 2021 SAP SE
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

from oslo_config import cfg
from neutron.conf import service

from networking_f5._i18n import _


F5_OPTS = [
    cfg.StrOpt('backend',
               default='icontrol',
               choices=['do', 'icontrol', 'noop'],
               help=_('Backend driver for BigIP F5 communication')),
    cfg.FloatOpt('sync_interval', default=90,
                 help=_('Seconds between full sync.')),
    cfg.FloatOpt('cleanup_interval', default=600,
                 help=_('Seconds between selfip cleanups.')),
    cfg.FloatOpt('selfip_interval', default=1200,
                 help=_('Seconds between selfip sync.')),
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
                help=_("Enables hardware syncookie mode on a VLAN. When "
                       "enabled, the hardware per-VLAN SYN cookie protection "
                       "will be triggered when the certain traffic threshold "
                       "is reached on supported platforms.")),
    cfg.IntOpt('syn_flood_rate_limit',
               default=2000,
               help=_("Specifies the max number of SYN flood packets per "
                      "second received on the VLAN before the hardware "
                      "per-VLAN SYN cookie protection is triggered.")),
    cfg.IntOpt('syncache_threshold',
               default=32000,
               help=_("Specifies the number of outstanding SYN packets on "
                      "the VLAN that will trigger the hardware per-VLAN SYN "
                      "cookie protection.")),
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

cfg.CONF.register_opts(F5_OPTS, 'F5')
cfg.CONF.register_opts(F5_VMCP_OPTS, 'F5_VCMP')
cfg.CONF.register_opts(service.RPC_EXTRA_OPTS)
