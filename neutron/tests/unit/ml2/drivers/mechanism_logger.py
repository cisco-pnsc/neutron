# Copyright (c) 2013 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api

LOG = log.getLogger(__name__)


class LoggerMechanismDriver(api.MechanismDriver):
    """Mechanism driver that logs all calls and parameters made.

    Generally used for testing and debugging.
    """

    def initialize(self):
        pass

    def _log_network_call(self, method_name, context):
        LOG.info(_("%(method)s called with network settings %(current)s "
                   "(original settings %(original)s) and "
                   "network segments %(segments)s"),
                 {'method': method_name,
                  'current': context.current(),
                  'original': context.original(),
                  'segments': context.network_segments()})

    def create_network_precommit(self, context):
        self._log_network_call("create_network_precommit", context)

    def create_network_postcommit(self, context):
        self._log_network_call("create_network_postcommit", context)

    def update_network_precommit(self, context):
        self._log_network_call("update_network_precommit", context)

    def update_network_postcommit(self, context):
        self._log_network_call("update_network_postcommit", context)

    def delete_network_precommit(self, context):
        self._log_network_call("delete_network_precommit", context)

    def delete_network_postcommit(self, context):
        self._log_network_call("delete_network_postcommit", context)

    def _log_port_call(self, method_name, context):
        network_context = context.network()
        LOG.info(_("%(method)s called with port settings %(current)s "
                   "(original settings %(original)s) on network %(network)s"),
                 {'method': method_name,
                  'current': context.current(),
                  'original': context.original(),
                  'network': network_context.current()})

    def create_port_precommit(self, context):
        self._log_port_call("create_port_precommit", context)

    def create_port_postcommit(self, context):
        self._log_port_call("create_port_postcommit", context)

    def update_port_precommit(self, context):
        self._log_port_call("update_port_precommit", context)

    def update_port_postcommit(self, context):
        self._log_port_call("update_port_postcommit", context)

    def delete_port_precommit(self, context):
        self._log_port_call("delete_port_precommit", context)

    def delete_port_postcommit(self, context):
        self._log_port_call("delete_port_postcommit", context)
