# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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


import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.db import db_base_plugin_v2 as base_db
from neutron.db.loadbalancer import loadbalancer_db as lbaas_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import lbaas_ssl
from neutron.extensions import loadbalancer
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


class SSLPolicy(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):

    """Represents a v2 neutron SSL Policy.

    SSL Policy may be associated to several vips.
    Vip can be associated with one SSL Policy only.
    """
    __tablename__ = 'sslpolicies'

    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    front_end_enabled = sa.Column(sa.Boolean(), nullable=False)
    front_end_protocols = sa.Column(sa.String(64))
    front_end_cipher_suites = sa.Column(sa.String(512))
    back_end_enabled = sa.Column(sa.Boolean(), nullable=False)
    back_end_protocols = sa.Column(sa.String(64))
    back_end_cipher_suites = sa.Column(sa.String(512))

    vips = orm.relationship(lbaas_db.Vip,
                            cascade='all', lazy="joined",
                            primaryjoin="Vip.ssl_policy_id==SSLPolicy.id")


class SSLCertificate(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):

    """Represents a v2 neutron SSL Certificate.

    SSL Certificate may be associated to 0..N vips
    Vip can be associated with 0..M certificates.
    """

    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    certificate = sa.Column(sa.Text(4096), nullable=False)
    passphrase = sa.Column(sa.String(128))
    certificate_chain = sa.Column(sa.Text(20480))

    vips = orm.relationship(
        "VipSSLCertificateAssociation",
        cascade="all", lazy="joined"
    )


class SSLTrustedCertificate(model_base.BASEV2,
                            models_v2.HasId, models_v2.HasTenant):

    """Represents a v2 neutron SSL Trusted Certificate.

    SSL Trusted Certificate may be associated to 0..N vips
    Vip can be associated with 0..M trusted certificates.
    """

    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    certificate = sa.Column(sa.String(4096))

    vips = orm.relationship(
        "VipSSLTrustedCertificateAssociation",
        cascade="all", lazy="joined"
    )


class VipSSLCertificateAssociation(model_base.BASEV2,
                                   models_v2.HasStatusDescription):

    """Many-to-many association between Vip and SSL certificate classes."""

    vip_id = sa.Column(sa.String(36),
                       sa.ForeignKey("vips.id"),
                       primary_key=True)
    ssl_certificate_id = sa.Column(sa.String(36),
                                   sa.ForeignKey("sslcertificates.id"),
                                   primary_key=True)


class VipSSLTrustedCertificateAssociation(model_base.BASEV2,
                                          models_v2.HasStatusDescription):

    """Many-to-many association between Vip
    and SSLTrustedCertificate classes.
    """

    vip_id = sa.Column(sa.String(36),
                       sa.ForeignKey("vips.id"),
                       primary_key=True)
    ssl_trusted_certificate_id = sa.Column(
        sa.String(36),
        sa.ForeignKey("ssltrustedcertificates.id"),
        primary_key=True
    )

setattr(lbaas_db.Vip, 'ssl_policy_id',
        sa.Column(sa.String(36), sa.ForeignKey('sslpolicies.id'),
                  default=None, nullable=True))

setattr(lbaas_db.Vip, 'ssl_certificate_ids',
        orm.relationship(
            VipSSLCertificateAssociation,
            uselist=True,
            lazy="joined",
            primaryjoin="Vip.id==VipSSLCertificateAssociation.vip_id",
            foreign_keys=[VipSSLCertificateAssociation.vip_id]
        ))

setattr(lbaas_db.Vip, 'ssl_trusted_certificate_ids',
        orm.relationship(
            VipSSLTrustedCertificateAssociation,
            uselist=True,
            lazy="joined",
            primaryjoin="Vip.id==VipSSLTrustedCertificateAssociation.vip_id",
            foreign_keys=[VipSSLTrustedCertificateAssociation.vip_id]
        ))


class LBaasSSLDbMixin(lbaas_ssl.LbaasSSLPluginBase, base_db.CommonDbMixin):
    def _extend_vip_dict_ssl(self, vip_res, vip_db):
        vip_res['ssl_policy_id'] = vip_db['ssl_policy_id']

        vip_res['ssl_certificate_ids'] = [
            cert['ssl_certificate_id'] for cert
            in vip_db['ssl_certificate_ids']]

        vip_res['ssl_trusted_certificate_ids'] = [
            cert['ssl_trusted_certificate_id'] for cert
            in vip_db['ssl_trusted_certificate_ids']]

    lbaas_db.LoadBalancerPluginDb.register_dict_extend_funcs(
        loadbalancer.VIPS, ['_extend_vip_dict_ssl'])

    def update_vip_ssl_assocs_status(self, context, vip_id,
                                     status, status_description=None):
        with context.session.begin(subtransactions=True):
            assocs = self._get_vip_ssl_assocs(
                context, VipSSLCertificateAssociation, vip_id)
            assocs.extend(self._get_vip_ssl_assocs(
                context, VipSSLTrustedCertificateAssociation, vip_id))
            for assoc in assocs:
                if assoc.status != status:
                    assoc.status = status
                if status_description or assoc['status_description']:
                    assoc.status_description = status_description

    def _get_ssl_resource(self, context, model, id):
        try:
            r = self._get_by_id(context, model, id)
        except exc.NoResultFound:
            if issubclass(model, lbaas_db.Vip):
                raise loadbalancer.VipNotFound(vip_id=id)
            if issubclass(model, lbaas_db.Pool):
                raise loadbalancer.PoolNotFound(pool_id=id)
            if issubclass(model, SSLPolicy):
                raise lbaas_ssl.SSLPolicyNotFound(policy_id=id)
            elif issubclass(model, SSLCertificate):
                raise lbaas_ssl.SSLCertificateNotFound(certificate_id=id)
            elif issubclass(model, SSLTrustedCertificate):
                raise lbaas_ssl.SSLTrustedCertificateNotFound(
                    certificate_id=id)
            else:
                raise
        return r

    def _make_ssl_policy_dict(self, ssl_policy, fields=None):
        res = {'id': ssl_policy['id'],
               'tenant_id': ssl_policy['tenant_id'],
               'name': ssl_policy['name'],
               'description': ssl_policy['description'],
               'front_end_enabled': ssl_policy['front_end_enabled'],
               'front_end_protocols': ssl_policy['front_end_protocols'],
               'front_end_cipher_suites':
               ssl_policy['front_end_cipher_suites'],
               'back_end_enabled': ssl_policy['back_end_enabled'],
               'back_end_protocols': ssl_policy['back_end_protocols'],
               'back_end_cipher_suites': ssl_policy['back_end_cipher_suites']}
        res['vips'] = [{'vip_id': v['id'],
                        'status': v['status'],
                        'status_description': v['status_description']}
                       for v in ssl_policy.vips]
        return self._fields(res, fields)

    def create_ssl_policy(self, context, ssl_policy):
        p = ssl_policy['ssl_policy']
        tenant_id = self._get_tenant_id_for_create(context, p)
        with context.session.begin(subtransactions=True):
            policy_db = SSLPolicy(id=uuidutils.generate_uuid(),
                                  tenant_id=tenant_id,
                                  name=p['name'],
                                  front_end_enabled=p['front_end_enabled'],
                                  front_end_protocols=p['front_end_protocols'],
                                  front_end_cipher_suites=
                                  p['front_end_cipher_suites'],
                                  back_end_enabled=p['back_end_enabled'],
                                  back_end_protocols=p['back_end_protocols'],
                                  back_end_cipher_suites=
                                  p['back_end_cipher_suites'])
            context.session.add(policy_db)
        return self._make_ssl_policy_dict(policy_db)

    def update_ssl_policy(self, context, id, ssl_policy):
        p = ssl_policy['ssl_policy']
        with context.session.begin(subtransactions=True):
            policy_db = self._get_ssl_resource(context, SSLPolicy, id)
            self.assert_modification_allowed(policy_db)
            if p:
                policy_db.update(p)
            return self._make_ssl_policy_dict(policy_db)

    def delete_ssl_policy(self, context, id):
        with context.session.begin(subtransactions=True):
            policy_db = self._get_ssl_resource(context, SSLPolicy, id)

            # Ensure that the policy is not used
            try:
                context.session.delete(policy_db)
                context.session.flush()
            except sa.IntegrityError:
                raise lbaas_ssl.SSLPolicyInUse(policy_id=id)

    def get_ssl_policy(self, context, id, fields=None):
        policy = self._get_ssl_resource(context, SSLPolicy, id)
        return self._make_ssl_policy_dict(policy, fields)

    def get_ssl_policies(self, context, filters=None, fields=None):
        return self._get_collection(context, SSLPolicy,
                                    self._make_ssl_policy_dict,
                                    filters=filters, fields=fields)

    def _make_ssl_certificate_dict(self, ssl_certificate, fields=None):
        res = {'id': ssl_certificate['id'],
               'name': ssl_certificate['name'],
               'description': ssl_certificate['description'],
               'tenant_id': ssl_certificate['tenant_id'],
               'certificate': ssl_certificate['certificate'],
               'passphrase': ssl_certificate['passphrase'],
               'certificate_chain': ssl_certificate['certificate_chain']}
        res['vips'] = [{'vip_id': v['vip_id'],
                        'status': v['status'],
                        'status_description': v['status_description']}
                       for v in ssl_certificate.vips]

        return self._fields(res, fields)

    def create_ssl_certificate(self, context, ssl_certificate):
        cert = ssl_certificate['ssl_certificate']
        tenant_id = self._get_tenant_id_for_create(context, cert)
        with context.session.begin(subtransactions=True):
            certificate_db = SSLCertificate(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=cert['name'],
                certificate=cert['certificate'],
                passphrase=cert['passphrase'],
                certificate_chain=cert['certificate_chain']
            )
            context.session.add(certificate_db)
        return self._make_ssl_certificate_dict(certificate_db)

    def update_ssl_certificate(self, context, id, ssl_certificate):
        c = ssl_certificate['ssl_certificate']
        with context.session.begin(subtransactions=True):
            certificate_db = self._get_ssl_resource(context,
                                                    SSLCertificate, id)
            if c:
                certificate_db.update(c)
            return self._make_ssl_certificate_dict(certificate_db)

    def delete_ssl_certificate(self, context, id):
        with context.session.begin(subtransactions=True):
            certificate = self._get_ssl_resource(context, SSLCertificate, id)

            # Ensure that the certificate is not used
            try:
                context.session.delete(certificate)
                context.session.flush()
            except sa.IntegrityError:
                raise lbaas_ssl.SSLCertificateInUse(certificate_id=id)

    def get_ssl_certificate(self, context, id, fields=None):
        cert = self._get_ssl_resource(context, SSLCertificate, id)
        return self._make_ssl_certificate_dict(cert, fields)

    def get_ssl_certificates(self, context, filters=None, fields=None):
        return self._get_collection(context, SSLCertificate,
                                    self._make_ssl_certificate_dict,
                                    filters=filters, fields=fields)

    def get_vip_ssl_certificates(self, context, vip_id):
        assocs = self._get_vip_ssl_assocs(context,
                                          VipSSLCertificateAssociation,
                                          vip_id)
        return self.get_ssl_certificates(
            context,
            filters={'id': [assoc['ssl_certificate_id'] for assoc in assocs]})

    def _make_ssl_trusted_certificate_dict(self, ssl_trusted_certificate,
                                           fields=None):
        res = {'id': ssl_trusted_certificate['id'],
               'tenant_id': ssl_trusted_certificate['tenant_id'],
               'name': ssl_trusted_certificate['name'],
               'description': ssl_trusted_certificate['description'],
               'certificate': ssl_trusted_certificate['certificate']}
        res['vips'] = [{'vip_id': v['vip_id'],
                        'status': v['status'],
                        'status_description': v['status_description']}
                       for v in ssl_trusted_certificate.vips]
        return self._fields(res, fields)

    def create_ssl_trusted_certificate(self, context,
                                       ssl_trusted_certificate):
        c = ssl_trusted_certificate['ssl_trusted_certificate']
        tenant_id = self._get_tenant_id_for_create(context, c)
        with context.session.begin(subtransactions=True):
            cert_db = SSLTrustedCertificate(id=uuidutils.generate_uuid(),
                                            tenant_id=tenant_id,
                                            name=c['name'],
                                            certificate=c['certificate'])
            context.session.add(cert_db)
        return self._make_ssl_trusted_certificate_dict(cert_db)

    def update_ssl_trusted_certificate(self, context, id,
                                       ssl_trusted_certificate):
        c = ssl_trusted_certificate['ssl_trusted_certificate']
        with context.session.begin(subtransactions=True):
            trusted_cert_db = self._get_ssl_resource(context,
                                                     SSLTrustedCertificate, id)
            self.assert_modification_allowed(trusted_cert_db)
            if c:
                trusted_cert_db.update(c)
            return self._make_ssl_trusted_certificate_dict(
                trusted_cert_db)

    def delete_ssl_trusted_certificate(self, context, id):
        with context.session.begin(subtransactions=True):
            cert_db = self._get_ssl_resource(context,
                                             SSLTrustedCertificate, id)

            # Ensure that the trusted certificate is not used
            try:
                context.session.delete(cert_db)
                context.session.flush()
            except sa.IntegrityError:
                raise lbaas_ssl.SSLTrustedCertificateInUse(certificate_id=id)

    def get_ssl_trusted_certificate(self, context, id, fields=None):
        cert = self._get_ssl_resource(context, SSLTrustedCertificate, id)
        return self._make_ssl_trusted_certificate_dict(cert, fields)

    def get_ssl_trusted_certificates(self, context,
                                     filters=None, fields=None):
        return self._get_collection(context, SSLTrustedCertificate,
                                    self._make_ssl_trusted_certificate_dict,
                                    filters=filters, fields=fields)

    def get_vip_ssl_trusted_certificates(self, context, vip_id):
        assocs = self._get_vip_ssl_assocs(context,
                                          VipSSLTrustedCertificateAssociation,
                                          vip_id)
        return self.get_ssl_trusted_certificates(
            context,
            filters={'id': [assoc['ssl_trusted_certificate_id']
                     for assoc in assocs]})

    #VIP-SSL Association DB access
    def create_vip_ssl_association(self, context,
                                   ssl_association, vip_id):
        if ssl_association['ssl_association']['ssl_policy']:
            policy_id = ssl_association['ssl_association'][
                'ssl_policy']['id']
        else:
            policy_id = None

        cert_ids = [cert['id']
                    for cert in ssl_association[
                        'ssl_association']['ssl_certificates']]
        trusted_cert_ids = [cert['id'] for cert
                            in ssl_association['ssl_association']
                                ['ssl_trusted_certificates']]

        policy = self._update_vip_ssl_policy(context,
                                             policy_id, vip_id)
        certificates = self._update_vip_ssl_certificates(context,
                                                         cert_ids, vip_id)
        trusted_certificates = self._update_vip_ssl_trusted_certificates(
            context, trusted_cert_ids, vip_id
        )

        res = {'ssl_policy': policy,
               'ssl_certificates': certificates,
               'ssl_trusted_certificates': trusted_certificates}
        return res

    def delete_vip_ssl_association(self, context, id, vip_id):
        policy = self._update_vip_ssl_policy(context,
                                             None, vip_id)
        certificates = self._update_vip_ssl_certificates(context,
                                                         [], vip_id)
        trusted_certificates = self._update_vip_ssl_trusted_certificates(
            context, [], vip_id
        )

        res = {'ssl_policy': policy,
               'ssl_certificates': certificates,
               'ssl_trusted_certificates': trusted_certificates}
        return res

    def get_vip_ssl_associations(self, context, id, vip_id, fields=None):
        pass

    def get_vip_ssl_association(self, context,id, vip_id, fields=None):
        vip = self._get_ssl_resource(context, lbaas_db.Vip, vip_id)
        
        cert_assocs = self._get_vip_ssl_assocs(
            context,
            VipSSLCertificateAssociation,
            vip_id)
        trust_cert_assocs = self._get_vip_ssl_assocs(
            context,
            VipSSLTrustedCertificateAssociation,
            vip_id)

        if vip.ssl_policy_id is not None:
            policy = {'id': vip.ssl_policy_id}
        else:
            policy = {'id': None}

        certs = [
            {'id': assoc['ssl_certificate_id']} for assoc in cert_assocs]
        trust_certs = [
            {'id': assoc['ssl_trusted_certificate_id']} for assoc
            in trust_cert_assocs]

        x = {'ssl_association': {
                'ssl_policy': policy,
                'ssl_certificates': certs,
                'ssl_trusted_certificates': trust_certs}}
        LOG.debug(x)
        return x

    def _get_vip_ssl_assocs(self, context, assoc_type, vip_id):
        assoc_qry = context.session.query(assoc_type)
        return assoc_qry.filter_by(vip_id=vip_id).all()

    def _get_vip_ssl_assocs_for_deletion(self, context, assoc_type, vip_id):
        assoc_qry = context.session.query(assoc_type)
        return assoc_qry.filter_by(vip_id=vip_id,
                                   status=constants.PENDING_DELETE).all()

    def _make_vip_ssl_policy_assoc_dict(self, assoc, fields=None):
        res = {'vip_id': assoc['vip_id'],
               'ssl_policy_id': assoc['ssl_policy_id']}
        return self._fields(res, fields)

    def _update_vip_ssl_policy(self, context, policy_id, vip_id):
        with context.session.begin(subtransactions=True):
            res = {'id': policy_id}
            vip = self._get_ssl_resource(context, lbaas_db.Vip, vip_id)

            if vip.ssl_policy_id is not None:
                if vip.ssl_policy_id == policy_id:
                    return res
                else:
                    self.assert_modification_allowed(vip)
                    vip.ssl_policy_id = None

            if policy_id is not None:
                self.assert_modification_allowed(vip)
                vip.ssl_policy_id = policy_id

            return res

    def _update_vip_ssl_certificates(self, context, new_cert_ids, vip_id):
        with context.session.begin(subtransactions=True):
            vip = self._get_ssl_resource(context, lbaas_db.Vip, vip_id)
            assocs = self._get_vip_ssl_assocs(context,
                                              VipSSLCertificateAssociation,
                                              vip_id)

            new_certs = []
            for assoc in assocs:
                self.assert_modification_allowed(assoc)
                if assoc.ssl_certificate_id in new_cert_ids:
                    assoc.status = constants.PENDING_CREATE
                    new_cert_ids.remove(assoc.ssl_certificate_id)
                    new_certs.append({'id': assoc.ssl_certificate_id})
                else:
                    assoc.status = constants.PENDING_DELETE

            for cert_id in new_cert_ids:
                assoc = VipSSLCertificateAssociation(
                    vip_id=vip_id,
                    ssl_certificate_id=cert_id,
                    status=constants.PENDING_CREATE
                )
                vip.ssl_certificate_ids.append(assoc)
                new_certs.append({'id': cert_id})

        return new_certs

    def _update_vip_ssl_trusted_certificates(self, context, cert_ids, vip_id):
        with context.session.begin(subtransactions=True):
            vip = self._get_ssl_resource(context, lbaas_db.Vip, vip_id)
            assocs = self._get_vip_ssl_assocs(
                context,
                VipSSLTrustedCertificateAssociation,
                vip_id
            )

            certificates = []
            for assoc in assocs:
                self.assert_modification_allowed(assoc)
                if assoc.ssl_trusted_certificate_id in cert_ids:
                    assoc.status = constants.PENDING_CREATE
                    cert_ids.remove(assoc.ssl_trusted_certificate_id)
                    certificates.append(
                        {'id': assoc.ssl_trusted_certificate_id})
                else:
                    assoc.status = constants.PENDING_DELETE

            for cert_id in cert_ids:
                assoc = VipSSLTrustedCertificateAssociation(
                    vip_id=vip_id,
                    ssl_trusted_certificate_id=cert_id,
                    status=constants.PENDING_CREATE
                )
                vip.ssl_trusted_certificate_ids.append(assoc)
                certificates.append({'id': cert_id})

        res = certificates
        return res

    def _remove_pending_delete_vip_ssl(self, context, vip_id):
        with context.session.begin(subtransactions=True):
            assocs = self._get_vip_ssl_assocs_for_deletion(
                context, VipSSLCertificateAssociation, vip_id
            )
            for assoc in assocs:
                context.session.delete(assoc)

            assocs = self._get_vip_ssl_assocs_for_deletion(
                context, VipSSLTrustedCertificateAssociation, vip_id
            )
            for assoc in assocs:
                context.session.delete(assoc)
