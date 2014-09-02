# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 OpenStack Foundation.
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
#
# @author: Evgeny Fedoruk, Radware, Inc

import abc

import six

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.api.v2 import resource_helper
from neutron.common import exceptions as qexception
from neutron.extensions import loadbalancer
from neutron import manager
from neutron.plugins.common import constants
from neutron.services.service_base import ServicePluginBase


# SSL Exceptions
class SSLPolicyNotFound(qexception.NotFound):
    message = _("SSL Policy %(policy_id)s could not be found")


class SSLPolicyInUse(qexception.InUse):
    message = _("SSL Policy %(policy_id)s is still associated with vips")


class SSLCertificateNotFound(qexception.NotFound):
    message = _("SSL Certificate %(certificate_id)s could not be found")


class SSLCertificateInUse(qexception.InUse):
    message = _("SSL Certificate %(certificate_id)s is still associated "
                "with vips")


class SSLTrustedCertificateNotFound(qexception.NotFound):
    message = _("SSL Trusted Certificate %(certificate_id)s "
                "could not be found")


class SSLTrustedCertificateInUse(qexception.InUse):
    message = _("SSL Trusted Certificate %(certificate_id)s "
                "is still associated with vips")


class VipSSLCertificateAssociationNotFound(qexception.NotFound):
    message = _("Vip %(vip_id)s is not associated "
                "with SSL Certificate %(certificate_id)s")


class VipSSLCertificateAssociationExists(qexception.Conflict):
    message = _("SSL Certificate %(certificate_id)s "
                "is already associated with vip %(vip_id)s")


class VipSSLTrustedCertificateAssociationNotFound(qexception.NotFound):
    message = _("Vip %(vip_id)s is not associated "
                "with SSL Trusted Certificate %(certificate_id)s")


class VipSSLTrustedCertificateAssociationExists(qexception.Conflict):
    message = _("SSL Trusted Certificate %(certificate_id)s "
                "is already associated with vip %(vip_id)s")

RESOURCE_ATTRIBUTE_MAP = {
    'ssl_policies': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '',
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'default': '',
                        'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'front_end_enabled': {'allow_post': True, 'allow_put': True,
                              'default': True,
                              'convert_to': attr.convert_to_boolean,
                              'is_visible': True},
        'front_end_protocols': {'allow_post': True, 'allow_put': True,
                                'validate': {'type:string': None},
                                'is_visible': True},
        'front_end_cipher_suites': {'allow_post': True, 'allow_put': True,
                                    'validate': {'type:string': None},
                                    'default': '',
                                    'is_visible': True},
        'back_end_enabled': {'allow_post': True, 'allow_put': True,
                             'default': True,
                             'convert_to': attr.convert_to_boolean,
                             'is_visible': True},
        'back_end_protocols': {'allow_post': True, 'allow_put': True,
                               'validate': {'type:string': None},
                               'is_visible': True},
        'back_end_cipher_suites': {'allow_post': True, 'allow_put': True,
                                   'validate': {'type:string': None},
                                   'default': '',
                                   'is_visible': True},
        'vips': {'allow_post': False, 'allow_put': False,
                 'default': None,
                 'validate': {'type:uuid_list': None},
                 'convert_to': attr.convert_to_list,
                 'is_visible': True}
    },
    'ssl_certificates': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'default': '',
                        'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'certificate': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'passphrase': {'allow_post': True, 'allow_put': True,
                       'validate': {'type:string': None},
                       'is_visible': True, 'default': ''},
        'certificate_chain': {'allow_post': True, 'allow_put': True,
                              'validate': {'type:string': None},
                              'is_visible': True, 'default': ''},
        'vips': {'allow_post': False, 'allow_put': False,
                 'default': None,
                 'validate': {'type:uuid_list': None},
                 'convert_to': attr.convert_to_list,
                 'is_visible': True}
    },
    'ssl_trusted_certificates': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '',
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'default': '',
                        'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'certificate': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'default': '',
                        'is_visible': True},
        'vips': {'allow_post': False, 'allow_put': False,
                 'default': None,
                 'validate': {'type:uuid_list': None},
                 'convert_to': attr.convert_to_list,
                 'is_visible': True}
    }
}

SUB_RESOURCE_ATTRIBUTE_MAP = {
    'ssl_associations': {
        'parent': {'collection_name': 'vips',
                   'member_name': 'vip'},
        'parameters': {
            'id': {
                'allow_post': True, 'allow_put': False,
                'validate': {'type:uuid': None},
                'is_visible': True},
            'tenant_id': {
                'allow_post': True, 'allow_put': False,
                'validate': {'type:string': None},
                'required_by_policy': True,
                'is_visible': True
            },
            'ssl_policy': {
                'allow_post': True, 'allow_put': False,
                'is_visible': True,
                'validate': {
                    'type:dict': {
                        'id': {'type:uuid': None}
                    }
                }
            },
            'ssl_certificates': {
                'allow_post': True, 'allow_put': False,
                'is_visible': True,
                'validate': {
                    'type:list_or_empty': {
                        'is_visible': True,
                        'type:dict': {
                            'id': {'type:uuid': None},
                            'private_key': {'type:string': None}
                        }
                    }
                }
            },
            'ssl_trusted_certificates': {
                'allow_post': True, 'allow_put': False,
                'is_visible': True,
                'validate': {
                    'type:list_or_empty': {
                        'is_visible': True,
                        'type:dict': {
                            'id': {'type:uuid': None}
                        }
                    }
                }
            }
        }
    }
}

EXTENDED_ATTRIBUTES_2_0 = {
    'vips': {
        'ssl_policy_id':
            {'allow_post': True, 'allow_put': True,
             'default': None,
             'validate': {'type:uuid_or_none': None},
             'is_visible': True},
        'ssl_certificate_ids':
            {'allow_post': True, 'allow_put': True,
             'default': [],
             'validate': {'type:uuid_list': None},
             'convert_to': attr.convert_to_list,
             'is_visible': True},
        'ssl_trusted_certificate_ids':
            {'allow_post': True, 'allow_put': True,
             'default': [],
             'validate': {'type:uuid_list': None},
             'convert_to': attr.convert_to_list,
             'is_visible': True}
    }
}


class Lbaas_ssl(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Loadbalancing service SSL extension"

    @classmethod
    def get_alias(cls):
        return "lbaas-ssl"

    @classmethod
    def get_description(cls):
        #TODO(Evgeny Fedoruk)
        return ("Extension for Loadbalancing service SSL")

    @classmethod
    def get_namespace(cls):
        #TODO(Evgeny Fedoruk) should be changed to specific link
        return "http://wiki.openstack.org/neutron/LBaaS/API_1.0"

    @classmethod
    def get_updated(cls):
        return "2014-13-01T10:00:00-00:00"

    @classmethod
    def get_resources(cls, ext_plugin=None):
        special_plurals = {
            'ssl_policies': 'ssl_policy',
            'ssl_certificates': 'ssl_certificate',
            'ssl_trusted_certificates': 'ssl_trusted_certificate',
            'ssl_associations': 'ssl_association'
        }
        attr.PLURALS.update(special_plurals)

        plugin = ext_plugin or manager.NeutronManager.get_service_plugins()[
            constants.LOADBALANCER]

        plural_mappings = resource_helper.build_plural_mappings(
            special_plurals, RESOURCE_ATTRIBUTE_MAP)

        resources = resource_helper.build_resource_info(plural_mappings,
                                                        RESOURCE_ATTRIBUTE_MAP,
                                                        constants.LOADBALANCER,
                                                        ext_plugin=plugin)

        for collection_name in SUB_RESOURCE_ATTRIBUTE_MAP:
            resource_name = special_plurals[collection_name]
            parent = SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].get('parent')
            params = SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].get(
                'parameters')

            controller = base.create_resource(collection_name, resource_name,
                                              plugin, params,
                                              allow_bulk=True,
                                              parent=parent)

            resource = extensions.ResourceExtension(
                collection_name,
                controller, parent,
                path_prefix=constants.COMMON_PREFIXES[constants.LOADBALANCER],
                attr_map=params)
            resources.append(resource)

        return resources

    @classmethod
    def get_plugin_interface(cls):
        return loadbalancer.LoadBalancerPluginBase

    def update_attributes_map(self, attributes):
        super(Lbaas_ssl, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            #return EXTENDED_ATTRIBUTES_2_0
            return dict(EXTENDED_ATTRIBUTES_2_0.items() +
                        RESOURCE_ATTRIBUTE_MAP.items())
        else:
            return {}


#@six.add_metaclass(abc.ABCMeta)
class LbaasSSLPluginBase(ServicePluginBase):
    __metaclass__ = abc.ABCMeta

    def get_plugin_name(self):
        return constants.LOADBALANCER

    def get_plugin_type(self):
        return constants.LOADBALANCER

    def get_plugin_description(self):
        return 'LoadBalancer ssl extension service plugin'

    @abc.abstractmethod
    def create_ssl_policy(self, context, ssl_policy):
        pass

    @abc.abstractmethod
    def update_ssl_policy(self, context, id, ssl_policy):
        pass

    @abc.abstractmethod
    def delete_ssl_policy(self, context, id):
        pass

    @abc.abstractmethod
    def get_ssl_policy(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_ssl_policies(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def create_ssl_certificate(self, context, ssl_certificate):
        pass

    @abc.abstractmethod
    def update_ssl_certificate(self, context, id, ssl_certificate):
        pass

    @abc.abstractmethod
    def delete_ssl_certificate(self, context, id):
        pass

    @abc.abstractmethod
    def get_ssl_certificate(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_ssl_certificates(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def create_ssl_trusted_certificate(self, context,
                                       ssl_trusted_certificate):
        pass

    @abc.abstractmethod
    def update_ssl_trusted_certificate(self, context, id,
                                       ssl_trusted_certificate):
        pass

    @abc.abstractmethod
    def delete_ssl_trusted_certificate(self, context, id):
        pass

    @abc.abstractmethod
    def get_ssl_trusted_certificate(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_ssl_trusted_certificates(self, context,
                                     filters=None, fields=None):
        pass

    @abc.abstractmethod
    def create_vip_ssl_association(self, context,
                                   ssl_association, vip_id):
        pass

    @abc.abstractmethod
    def delete_vip_ssl_association(self, context, id, vip_id):
        pass

    @abc.abstractmethod
    def get_vip_ssl_association(self, context, id, vip_id, fields=None):
        pass

    @abc.abstractmethod
    def get_vip_ssl_associations(self, context, vip_id, fields=None):
        pass
