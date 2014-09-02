# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013, 2014 Intel Corporation.
# Copyright 2013, 2014 Isaku Yamahata <isaku.yamahata at intel com>
#                                     <isaku.yamahata at gmail com>
# All Rights Reserved.
#
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
# @author: Isaku Yamahata, Intel Corporation.

import eventlet
from oslo.config import cfg
import webob.exc
import pdb
from neutron.api.v2 import attributes
from neutron.common import driver_manager
from neutron.db.vm import vm_db
from neutron.extensions import servicevm
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.vm.mgmt_drivers import constants as mgmt_constants
from neutron.plugins.common import constants
from neutron import manager
from neutron.db import l3_db
from neutronclient.v2_0 import client 
LOG = logging.getLogger(__name__)


class ServiceVMMgmtMixin(object):
    OPTS = [
        cfg.MultiStrOpt(
            'mgmt_driver', default=[],
            help=_('MGMT driver to communicate with '
                   'Hosting Device/logical service '
                   'instance servicevm plugin will use')),
    ]
    cfg.CONF.register_opts(OPTS, 'servicevm')

    def __init__(self):
        super(ServiceVMMgmtMixin, self).__init__()
        self._mgmt_manager = driver_manager.DriverManager(
            'neutron.servicevm.mgmt.drivers', cfg.CONF.servicevm.mgmt_driver)

    def mgmt_address(self, context, device_dict):
        return self._mgmt_manager.invoke(
            self._mgmt_device_driver(device_dict), 'mgmt_address', plugin=self,
            context=context, device=device_dict)

    def mgmt_call(self, context, device_dict, kwargs):
        return self._mgmt_manager.invoke(
            self._mgmt_device_driver(device_dict), 'mgmt_call', plugin=self,
            context=context, device=device_dict, kwargs=kwargs)

    def mgmt_service_driver(self, context, device_dict, service_instance_dict):
        return self._mgmt_manager.invoke(
            self._mgmt_device_driver(device_dict), 'mgmt_service_driver',
            plugin=self, context=context, device=device_dict,
            service_instance=service_instance_dict)

    def mgmt_service_address(self, context, device_dict,
                             service_instance_dict):
        return self._mgmt_manager.invoke(
            self._mgmt_service_driver(service_instance_dict),
            'mgmt_service_address', plugin=self, context=context,
            device=device_dict, service_instance=service_instance_dict)

    def mgmt_service_call(self, context, device_dict, service_instance_dict,
                          kwargs):
        return self._mgmt_manager.invoke(
            self._mgmt_service_driver(service_instance_dict),
            'mgmt_service_call', plugin=self, context=context,
            device=device_dict, service_instance=service_instance_dict,
            kwargs=kwargs)


class ServiceVMPlugin(vm_db.ServiceResourcePluginDb, ServiceVMMgmtMixin):
    """ServiceVMPlugin which supports ServiceVM framework
    """
    OPTS = [
        cfg.MultiStrOpt(
            'device_driver', default=[],
            help=_('Hosting device drivers servicevm plugin will use')),
    ]
    cfg.CONF.register_opts(OPTS, 'servicevm')
    supported_extension_aliases = ['servicevm']

    def __init__(self):
        super(ServiceVMPlugin, self).__init__()
        self._pool = eventlet.GreenPool()
        self._device_manager = driver_manager.DriverManager(
            'neutron.servicevm.device.drivers',
            cfg.CONF.servicevm.device_driver)

    def spawn_n(self, function, *args, **kwargs):
        self._pool.spawn_n(function, *args, **kwargs)

    ###########################################################################
    # hosting device template

    def create_device_template(self, context, device_template):
        template = device_template['device_template']
        LOG.debug(_('template %s'), template)
        device_driver = template.get('device_driver')
        if not attributes.is_attr_set(device_driver):
            LOG.debug(_('hosting device driver must be specified'))
            raise servicevm.DeviceDriverNotSpecified()
        if device_driver not in self._device_manager:
            LOG.debug(_('unknown hosting device driver '
                        '%(device_driver)s in %(drivers)s'),
                      {'device_driver': device_driver,
                       'drivers': cfg.CONF.servicevm.device_driver})
            #raise servicevm.InvalidDeviceDriver(device_driver=device_driver)

        mgmt_driver = template.get('mgmt_driver')
        if not attributes.is_attr_set(mgmt_driver):
            LOG.debug(_('mgmt driver must be specified'))
            #raise servicevm.MgmtDriverNotSpecified()
        if mgmt_driver not in self._mgmt_manager:
            LOG.debug(_('unknown mgmt driver %(mgmt_driver)s in %(drivers)s'),
                      {'mgmt_driver': mgmt_driver,
                       'drivers': cfg.CONF.servicevm.mgmt_driver})
            #raise servicevm.InvalidMgmtDriver(mgmt_driver=mgmt_driver)

        service_types = template.get('service_types')
        scope =  template.get('scope')
        if not attributes.is_attr_set(service_types):
            LOG.debug(_('service type must be specified'))
            raise servicevm.ServiceTypesNotSpecified()
        for service_type in service_types:
            # TODO(yamahata):
            # framework doesn't know what services are valid for now.
            # so doesn't check it here yet.
            if scope=='global':
                isExist = self.check_global_policy_for_service(context,service_type['service_type'])
                if isExist:
                    user_msg = 'Global Deployment Policy for the service type \'%s\' exists' %(service_type['service_type'])
                    raise  webob.exc.HTTPBadRequest(user_msg) 
            tenantId=context.__dict__['tenant']
	    if self.isdevicetemplate_inTenant(context,service_type['service_type']):
		LOG.debug(_('Device Template for service type exists in tenant'))
                raise servicevm.deplomentpolicyExists()
            if service_type['service_type'] == 'l3router':
	        if self.isrouter_inTenant(context,tenantId):   
                    LOG.debug(_('service type exist in tenant'))
                    raise servicevm.Serviceinuse(service_type=service_type['service_type'])
            if service_type['service_type'] == 'lbaas':
                if self.isvip_inTenant(context,tenantId):
                    LOG.debug(_('service type exist in tenant'))
                    raise servicevm.Serviceinuse(service_type=service_type['service_type'])
        attribute_dict = template.get('attributes')
        mandatory_attributes = ['admin_user','admin_password','platform']
        all_attributes = ['enable_ha','admin_user','admin_password','platform','version','throughput_level','feature_level','availability_zone','availability_zone_primary','availability_zone_secondary','license_category']
        msg = attributes._verify_dict_keys(mandatory_attributes,attribute_dict,False)
        if msg:
            LOG.debug(msg)
            user_msg = 'Madatory attributes missing!!  Mandatory attributes are %s but given %s' %(mandatory_attributes,attribute_dict.keys())
            raise  webob.exc.HTTPBadRequest(user_msg)
        msg=self.validateAttr(attribute_dict,all_attributes)
        if msg:
            LOG.debug(msg)
            raise  webob.exc.HTTPBadRequest(msg)
            
        return super(ServiceVMPlugin, self).create_device_template(
            context, device_template)

    ###########################################################################
    # hosting device
    def delete_device_template(self, context, device_template_id):
	device_template=self.get_device_template(context, device_template_id)
        tenant_id=device_template['tenant_id']
        service_type=device_template['service_types'][0]
        if service_type['service_type'] == 'l3router':
            if self.isrouter_inTenant(context,tenant_id):
                LOG.debug(_('service type exist in tenant'))
                raise servicevm.Serviceinuse(service_type=service_type['service_type'])
        if service_type['service_type'] == 'lbaas':
            if self.isvip_inTenant(context,tenant_id):
                LOG.debug(_('service type exist in tenant'))
                raise servicevm.Serviceinuse(service_type=service_type['service_type'])
        super(ServiceVMPlugin, self).delete_device_template(
            context, device_template_id)
    def _create_device_wait(self, context, device_dict):
        driver_name = self._device_driver_name(device_dict)
        device_id = device_dict['id']
        instance_id = self._instance_id(device_dict)

        try:
            self._device_manager.invoke(
                driver_name, 'create_wait', plugin=self,
                context=context, device_id=instance_id)
        except servicevm.DeviceCreateWaitFailed:
            instance_id = None
            del device_dict['instance_id']

        if instance_id is None:
            mgmt_address = None
        else:
            mgmt_address = self.mgmt_address(context, device_dict)

        self._create_device_post(
            context, device_id, instance_id, mgmt_address,
            device_dict['service_context'])
        if instance_id is None:
            return

        kwargs = {
            mgmt_constants.KEY_ACTION: mgmt_constants.ACTION_CREATE,
            mgmt_constants.KEY_KWARGS: {'device': device_dict},
        }
        new_status = constants.ACTIVE
        try:
            self.mgmt_call(context, device_dict, kwargs)
        except Exception:
            new_status = constants.ERROR
        self._create_device_status(context, device_id, new_status)

    def _create_device(self, context, device):
        device_dict = self._create_device_pre(context, device)
        device_id = device_dict['id']
        driver_name = self._device_driver_name(device_dict)
        LOG.debug(_('device_dict %s'), device_dict)
        instance_id = self._device_manager.invoke(
            driver_name, 'create', plugin=self,
            context=context, device=device_dict)

        if instance_id is None:
            self._create_device_post(context, device_id, None, None)
            return

        device_dict['instance_id'] = instance_id
        return device_dict

    def create_device(self, context, device):
        device_dict = self._create_device(context, device)
        self.spawn_n(self._create_device_wait, context, device_dict)
        return device_dict

    # not for wsgi, but for service to creaste hosting device
    def create_device_sync(self, context, template_id, kwargs,
                           service_context):
        assert template_id is not None
        device = {
            'device': {
                'template_id': template_id,
                'kwargs': kwargs,
                'service_context': service_context,
            },
        }
        device_dict = self._create_device(context, device)
        if 'instance_id' not in device_dict:
            raise servicevm.DeviceCreateFailed(device_template_id=template_id)

        self._create_device_wait(context, device_dict)
        if 'instance_id' not in device_dict:
            raise servicevm.DeviceCreateFailed(device_template_id=template_id)

        return device_dict

    def _update_device_wait(self, context, device_dict):
        driver_name = self._device_driver_name(device_dict)
        instance_id = self._instance_id(device_dict)
        kwargs = {
            mgmt_constants.KEY_ACTION: mgmt_constants.ACTION_UPDATE,
            mgmt_constants.KEY_KWARGS: {'device': device_dict},
        }
        new_status = constants.ACTIVE
        try:
            self._device_manager.invoke(
                driver_name, 'update_wait', plugin=self,
                context=context, device_id=instance_id)
            self.mgmt_call(context, device_dict, kwargs)
        except Exception:
            new_status = constants.ERROR
        self._update_device_post(context, device_dict['id'], device_dict,
                                 new_status)

    def update_device(self, context, device_id, device):
        device_dict = self._update_device_pre(context, device_id, device)
        driver_name = self._device_driver_name(device_dict)
        instance_id = self._instance_id(device_dict)

        try:
            self._device_manager.invoke(driver_name, 'update', plugin=self,
                                        context=context, device_id=instance_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._update_device_post(
                    context, device_id, device, constants.ERROR)

        self.spawn_n(self._update_device_wait, context, device_dict)
        return device_dict

    def _delete_device_wait(self, context, device_dict):
        driver_name = self._device_driver_name(device_dict)
        instance_id = self._instance_id(device_dict)

        e = None
        try:
            self._device_manager.invoke(
                driver_name, 'delete_wait', plugin=self,
                context=context, device_id=instance_id)
        except Exception as e_:
            e = e_
        device_id = device_dict['id']
        self._delete_device_post(context, device_id, e)

    def delete_device(self, context, device_id):
        device_dict = self._delete_device_pre(context, device_id)
        driver_name = self._device_driver_name(device_dict)
        instance_id = self._instance_id(device_dict)
        kwargs = {
            mgmt_constants.KEY_ACTION: mgmt_constants.ACTION_DELETE,
            mgmt_constants.KEY_KWARGS: {'device': device_dict},
        }
        try:
            self.mgmt_call(context, device_dict, kwargs)
            self._device_manager.invoke(driver_name, 'delete', plugin=self,
                                        context=context, device_id=instance_id)
        except Exception as e:
            # TODO(yamahata): when the devaice is already deleted. mask
            # the error, and delete row in db
            # Other case mark error
            with excutils.save_and_reraise_exception():
                self._delete_device_post(context, device_id, e)

        self._delete_device_post(context, device_id, None)
        self.spawn_n(self._delete_device_wait, context, device_dict)

    ###########################################################################
    # logical service instance
    #
    def _create_service_instance_mgmt(
            self, context, device_dict, service_instance_dict):
        kwargs = {
            mgmt_constants.KEY_ACTION: mgmt_constants.ACTION_CREATE_SERVICE,
            mgmt_constants.KEY_KWARGS: {
                'device': device_dict,
                'service_instance': service_instance_dict,
            },
        }
        self.mgmt_call(context, device_dict, kwargs)

        mgmt_driver = self.mgmt_service_driver(
            context, device_dict, service_instance_dict)
        service_instance_dict['mgmt_driver'] = mgmt_driver
        mgmt_address = self.mgmt_service_address(
            context, device_dict, service_instance_dict)
        service_instance_dict['mgmt_address'] = mgmt_address
        LOG.debug(_('service_instance_dict '
                    '%(service_instance_dict)s '
                    'mgmt_driver %(mgmt_driver)s '
                    'mgmt_address %(mgmt_address)s'),
                  {'service_instance_dict':
                   service_instance_dict,
                   'mgmt_driver': mgmt_driver, 'mgmt_address': mgmt_address})
        self._update_service_instance_mgmt(
            context, service_instance_dict['id'], mgmt_driver, mgmt_address)

        self.mgmt_service_call(
            context, device_dict, service_instance_dict, kwargs)

    def _create_service_instance_by_type(
            self, context, device_dict,
            name, service_type, service_table_id):
        LOG.debug(_('device_dict %(device_dict)s '
                    'service_type %(service_type)s'),
                  {'device_dict': device_dict,
                   'service_type': service_type})
        service_type_id = [
            s['id'] for s in
            device_dict['device_template']['service_types']
            if s['service_type'].upper() == service_type.upper()][0]

        service_instance_param = {
            'name': name,
            'service_table_id': service_table_id,
            'service_type': service_type,
            'service_type_id': service_type_id,
        }
        service_instance_dict = self._create_service_instance(
            context, device_dict['id'], service_instance_param)

        self._create_service_instance_mgmt(
            context, device_dict, service_instance_dict)
        return service_instance_dict

    # for service drivers. e.g. hosting_driver of loadbalancer
    def create_service_instance_by_type(self, context, device_dict,
                                        name, service_type, service_table_id):
        self._update_device_pre(context, device_dict['id'], device_dict)
        new_status = constants.ACTIVE
        try:
            return self._create_service_instance_by_type(
                context, device_dict, name, service_type,
                service_table_id)
        except Exception:
            LOG.exception(_('create_service_instance_by_type'))
            new_status = constants.ERROR
        finally:
            self._update_device_post(context, device_dict['id'], device_dict,
                                     new_status)

    def _create_service_instance_wait(self, context, device_id,
                                      service_instance_dict):
        device_dict = self.get_device(context, device_id)

        new_status = constants.ACTIVE
        try:
            self._create_service_instance_mgmt(
                context, device_dict, service_instance_dict)
        except Exception:
            LOG.exception(_('_create_service_instance_mgmt'))
            new_status = constants.ERROR
        self._update_service_instance_post(
            context, service_instance_dict['id'], new_status)

    # for service drivers. e.g. hosting_driver of loadbalancer
    def _create_service_instance(self, context, device_id,
                                 service_instance_param):
        service_instance_dict = super(
            ServiceVMPlugin, self)._create_service_instance(
                context, device_id, service_instance_param)
        self.spawn_n(self._create_service_instance_wait, context,
                     device_id, service_instance_dict)
        return service_instance_dict

    def create_service_instance(self, context, service_instance):
        raise webob.exc.HTTPMethodNotAllowed()

    def _update_service_instance_wait(self, context, service_instance_dict,
                                      mgmt_kwargs, callback, errorback):
        devices = service_instance_dict['devices']
        assert len(devices) == 1
        device_dict = self.get_device(context, devices[0])
        kwargs = {
            mgmt_constants.KEY_ACTION: mgmt_constants.ACTION_UPDATE_SERVICE,
            mgmt_constants.KEY_KWARGS: mgmt_kwargs,
        }
        try:
            self.mgmt_service_call(context, device_dict,
                                   service_instance_dict, kwargs)
            self.mgmt_call(context, device_dict, kwargs)
        except Exception:
            LOG.exception(_('mgmt call failed %s'), kwargs)
            self._update_service_instance_post(
                context, service_instance_dict['id'], constants.ERROR)
            if errorback:
                errorback()
        else:
            self._update_service_instance_post(
                context, service_instance_dict['id'], constants.ACTIVE)
            if callback:
                callback()

    # for service drivers. e.g. hosting_driver of loadbalancer
    def _update_service_instance(self, context, service_instance_id,
                                 mgmt_kwargs, callback, errorback):
        service_instance_dict = self._update_service_instance_pre(
            context, service_instance_id, {})
        self.spawn_n(self._update_service_instance_wait, context,
                     service_instance_dict, mgmt_kwargs, callback, errorback)

    # for service drivers. e.g. hosting_driver of loadbalancer
    def _update_service_table_instance(
            self, context, service_table_id, mgmt_kwargs, callback, errorback):

        _device_dict, service_instance_dict = self.get_by_service_table_id(
            context, service_table_id)
        self.spawn_n(self._update_service_instance_wait, context,
                     service_instance_dict, mgmt_kwargs, callback, errorback)

    def update_service_instance(self, context, service_instance_id,
                                service_instance):
        mgmt_kwargs = service_instance['service_instance'].get('kwarg', {})
        service_instance_dict = self._update_service_instance_pre(
            context, service_instance_id, service_instance)

        self.spawn_n(self._update_service_instance_wait, context,
                     service_instance_dict, mgmt_kwargs, None, None)
        return service_instance_dict

    def _delete_service_instance_wait(self, context, device, service_instance,
                                      mgmt_kwargs, callback, errorback):
        service_instance_id = service_instance['id']
        kwargs = {
            mgmt_constants.KEY_ACTION: mgmt_constants.ACTION_DELETE_SERVICE,
            mgmt_constants.KEY_KWARGS: mgmt_kwargs,
            'device': device,
            'service_instance': service_instance,
        }
        try:
            self.mgmt_service_call(context, device, service_instance, kwargs)
            self.mgmt_call(context, device, kwargs)
        except Exception:
            LOG.exception(_('mgmt call failed %s'), kwargs)
            self._update_service_instance_post(context, service_instance_id,
                                               constants.ERROR)
            if errorback:
                errorback()
        else:
            self._delete_service_instance_post(context, service_instance_id)
            if callback:
                callback()

    # for service drivers. e.g. hosting_driver of loadbalancer
    def _delete_service_table_instance(
            self, context, service_table_instance_id,
            mgmt_kwargs, callback, errorback):
        device, service_instance = self._device_plugin.get_by_service_table_id(
            context, service_table_instance_id)
        self._delete_service_instance_pre(context, service_instance['id'])
        self._pool_spawn_n(
            self._delete_service_instance_wait, context, device,
            service_instance, mgmt_kwargs, callback, errorback)

    def delete_service_instance(self, context, service_instance_id):
        raise webob.exc.HTTPMethodNotAllowed()
    def isrouter_inTenant(self,context,tenant_id):
        l3plugin =  manager.NeutronManager.get_service_plugins().get(constants.L3_ROUTER_NAT)
        lbaasplugin= manager.NeutronManager.get_service_plugins()[
            constants.LOADBALANCER]
        routers=l3plugin.get_routers( context)
        for router in routers:
            if router['tenant_id']==tenant_id:
	        return True
        return False
 
    def isvip_inTenant(self,context,tenant_id):
        lbaasplugin= manager.NeutronManager.get_service_plugins()[
            constants.LOADBALANCER]
        vips=lbaasplugin.get_vips(context)
        for vip in vips:
            if vip['tenant_id']==tenant_id:
                return True
        return False
    def isdevicetemplate_inTenant(self,context,service_type):
	device_templates = self.get_device_templates(context,None)
        for servicetypes in device_templates:
            if servicetypes['tenant_id'] == context.to_dict()['tenant_id']:
                service = servicetypes['service_types']
                service_name =service[0]
                if service_name['service_type']==service_type:
                    return True		
        return False

    def check_global_policy_for_service(self,context,service_type):
        nc=self.get_neutron_client()
        templates = nc.list_device_templates()
        device_templates = templates['device_templates']
        for servicetypes in device_templates:
            if servicetypes['tenant_id'] == constants.GLOBAL_DEVICE_TEMPLATE_TID:
                service = servicetypes['service_types']
                service_name =service[0]
                if service_name['service_type']==service_type:
                    return True

    def validateAttr(self,attribute_dict,supported_attributes):
        for attr,value in attribute_dict.items():
            if attr in supported_attributes:
                if attr=='enable_ha':
                    supported_values = ['true','false']
                    msg=attributes._validate_values(value,supported_values)
                    if msg:
                        msg = 'Unsupported value is given for the attribute \'enable_ha\' supported values are %s' % (supported_values)
                elif attr=='admin_user':
                    msg=self.isempty(attr,value)
                elif attr=='admin_password':
                    msg=self.isempty(attr,value) 
                elif attr == 'platform':
                    supported_platforms = ['Csr1000v','Netscaler1000V','l3agent']
                    msg=attributes._validate_values(value,supported_platforms)
                    if msg:
                        msg = 'Unsupported value is given for the attribute \'platform\' supported platforms are %s' % (supported_platforms)
                elif attr == 'availability_zone':
                    if 'enable_ha' in attribute_dict and attribute_dict['enable_ha']=='false':
                        LOG.debug('Availability zone set for Non HA')
                    else:
                        msg =' Attribute \'availibilty_zone\' is applicable only for Non-HA . Set attribute enable_ha = false'
                elif attr == 'availability_zone_primary' or attr == 'availability_zone_secondary':
                     if 'enable_ha' in attribute_dict and attribute_dict['enable_ha']=='true':
                        LOG.debug('Availability zone set for  HA')   
                     else:
                         msg ='Attribute \'%s\' is applicable only for HA . Set attribute enable_ha = true' % (attr)    
                else:
                    msg=None   
            else:
                msg = 'Unknown attribute \'%s\' supported attributes are %s'%(attr,supported_attributes)
            if msg:
                return msg
        return msg
    def isempty(self,attr,value):
        if value.strip()=='':
            msg = 'Attribute %s should not be empty' %(attr)
        else:
            msg = None
        return msg
    def get_neutron_client(self):
        try:
            auth_host = cfg.CONF.keystone_authtoken.auth_host
            auth_port = cfg.CONF.keystone_authtoken.auth_port
            admin_tenant_name = cfg.CONF.keystone_authtoken.admin_tenant_name
            admin_user = cfg.CONF.keystone_authtoken.admin_user
            admin_password = cfg.CONF.keystone_authtoken.admin_password
            nc = client.Client(username=admin_user,
                                 password=admin_password,
                                 tenant_name=admin_tenant_name,
                                 auth_url='http://'+auth_host+':'+str(auth_port)+'/v2.0')
            return nc
        except Exception:
            raise
 	    
