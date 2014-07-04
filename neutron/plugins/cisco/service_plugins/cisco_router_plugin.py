# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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
#
# @author: Bob Melander, Cisco Systems, Inc.

from oslo.config import cfg

from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import agents_db
from neutron.db import api as qdbapi
from neutron.db import db_base_plugin_v2
from neutron.db import model_base
import neutron.plugins
from neutron.plugins.cisco.db.l3 import device_handling_db
from neutron.plugins.cisco.db.l3 import l3_router_appliance_db
from neutron.plugins.cisco.l3.rpc import (l3_router_cfgagent_rpc_cb as
                                          l3_router_rpc)
from neutron.plugins.cisco.l3.rpc import devices_cfgagent_rpc_cb as devices_rpc
from neutron.plugins.cisco.l3.rpc import l3_rpc_agent_api_noop
from neutron.plugins.cisco.l3 import service_vm_lib
from neutron.plugins.common import constants


class CiscoRouterPluginRpcCallbacks(n_rpc.RpcCallback,
                                    l3_router_rpc.L3RouterCfgRpcCallbackMixin,
                                    devices_rpc.DeviceCfgRpcCallbackMixin):
    RPC_API_VERSION = '1.1'

    def __init__(self, plugin):
        super(CiscoRouterPluginRpcCallbacks, self).__init__()
        self._plugin = plugin


class CiscoRouterPlugin(db_base_plugin_v2.CommonDbMixin,
                        agents_db.AgentDbMixin,
                        l3_router_appliance_db.L3RouterApplianceDBMixin,
                        device_handling_db.DeviceHandlingMixin):

    """Implementation of Cisco L3 Router Service Plugin for Neutron.

    This class implements a L3 service plugin that provides
    router and floatingip resources and manages associated
    request/response.
    All DB functionality is implemented in class
    l3_router_appliance_db.L3RouterApplianceDBMixin.
    """
    supported_extension_aliases = ["router", "extraroute"]

    def __init__(self):
        qdbapi.register_models(base=model_base.BASEV2)
        self.setup_rpc()
        basepath = neutron.plugins.__path__[0]
        ext_paths = [basepath + '/cisco/extensions']
        cp = cfg.CONF.api_extensions_path
        to_add = ""
        for ext_path in ext_paths:
            if cp.find(ext_path) == -1:
                to_add += ':' + ext_path
        if to_add != "":
            cfg.CONF.set_override('api_extensions_path', cp + to_add)
        # for backlogging of non-scheduled routers
        self._setup_backlog_handling()
        auth_url = (cfg.CONF.keystone_authtoken.auth_protocol + "://" +
                    cfg.CONF.keystone_authtoken.auth_host + ":" +
                    str(cfg.CONF.keystone_authtoken.auth_port) + "/v2.0")
        u_name = cfg.CONF.keystone_authtoken.admin_user
        pw = cfg.CONF.keystone_authtoken.admin_password
        tenant = cfg.CONF.l3_admin_tenant
        self._svc_vm_mgr = service_vm_lib.ServiceVMManager(
            user=u_name, passwd=pw, l3_admin_tenant=tenant, auth_url=auth_url)

    def setup_rpc(self):
        # RPC support
        self.topic = topics.L3PLUGIN
        self.conn = n_rpc.create_connection(new=True)
        # Disable notifications from l3 base class to l3 agents
        self.l3_rpc_notifier = l3_rpc_agent_api_noop.L3AgentNotifyNoOp
        self.endpoints = [CiscoRouterPluginRpcCallbacks(self)]
        self.conn.create_consumer(self.topic, self.endpoints,
                                  fanout=False)
        # Consume from all consumers in threads
        self.conn.consume_in_threads()

    def get_plugin_type(self):
        return constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        return ("Cisco Router Service Plugin for basic L3 forwarding"
                " between (L2) Neutron networks and access to external"
                " networks via a NAT gateway.")
