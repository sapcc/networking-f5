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

from neutron_lib import constants

AGENT_BINARY = 'neutron-f5-agent'
AGENT_TYPE_F5 = 'F5 Agent'
TOPIC = 'f5'
VIF_TYPE_F5 = 'f5'
RPC_VERSION = '1.0'

DEVICE_OWNER_LISTENER = constants.DEVICE_OWNER_NETWORK_PREFIX + 'f5listener'
DEVICE_OWNER_SELFIP = constants.DEVICE_OWNER_NETWORK_PREFIX + 'f5selfip'
DEVICE_OWNER_LEGACY = constants.DEVICE_OWNER_NETWORK_PREFIX + 'f5lbaasv2'
PREFIX_SELFIP = 'port-'
PREFIX_NET = 'net-'
PREFIX_VLAN = 'vlan-'
