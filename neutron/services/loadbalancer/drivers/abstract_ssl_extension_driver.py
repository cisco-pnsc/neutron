# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Radware LTD.
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
# @author: Evgeny Fedoruk, Radware

import abc

import six


#@six.add_metaclass(abc.ABCMeta)
class LBaaSAbstractSSLDriver(object):
    """Abstract lbaas ssl driver that expose ~same API as lbaas ssl extension.

    SSL entities update actions will be habdled by the driver
    The entities are the dicts that are returned to the tenant.
    Create, Delete and Get are not part of the API - it will be handled
    by the dbmixin.
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def update_ssl_policy(self, context, ssl_policy, vip):
        pass

    @abc.abstractmethod
    def update_ssl_certificate(self, context, ssl_certificate, vip):
        pass

    @abc.abstractmethod
    def update_ssl_trusted_certificate(self, context,
                                       ssl_trusted_certificate, vip):
        pass

    @abc.abstractmethod
    def create_vip_ssl_association(self, context,
                                   ssl_policy, ssl_certificates,
                                   ssl_trusted_certificates, vip):
        """Driver should:
        Remove all PENDING_DELETE association to ssl policy, certificates
        and trusted certificates.
        use plugin._remove_pending_delete_vip_ssl()

        Update status of all PENDING_CREATE associations to ssl policy,
        certificates and trusted certificates
        use plugin.update_status()
        """
        pass

    @abc.abstractmethod
    def delete_vip_ssl_association(self, context, vip):
        """Driver should:
        Remove all PENDING_DELETE association to ssl policy, certificates
        and trusted certificates.
        use plugin._remove_pending_delete_vip_ssl
        """
        pass
