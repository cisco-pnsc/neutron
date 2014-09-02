# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 OpenStack Foundation
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

"""Adds SSL extension tables and modifies vip model with ssl_policy_id

Revision ID: 6815e9450v77
Revises: 1b837a7125a9 
Create Date: 2014-04-30 08:00:39.585946

"""

# revision identifiers, used by Alembic.
revision = '6815e9450v77'
down_revision = 'havana'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.services.loadbalancer.plugin.LoadBalancerPlugin'
]

from alembic import op
import sqlalchemy as sa


from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        u'sslpolicies',
        sa.Column(u'tenant_id', sa.String(255), nullable=True),
        sa.Column(u'id', sa.String(36), nullable=False),
        sa.Column(u'name', sa.String(255), nullable=True),
        sa.Column(u'description', sa.String(255), nullable=True),
        sa.Column(u'front_end_enabled', sa.Boolean(), nullable=False),
        sa.Column(u'front_end_protocols', sa.String(64)),
        sa.Column(u'front_end_cipher_suites', sa.String(512)),
        sa.Column(u'back_end_enabled', sa.Boolean(), nullable=False),
        sa.Column(u'back_end_protocols', sa.String(64)),
        sa.Column(u'back_end_cipher_suites', sa.String(512)),
        sa.PrimaryKeyConstraint(u'id'),
    )
    op.create_table(
        u'sslcertificates',
        sa.Column(u'tenant_id', sa.String(255), nullable=True),
        sa.Column(u'id', sa.String(36), nullable=False),
        sa.Column(u'name', sa.String(255), nullable=True),
        sa.Column(u'description', sa.String(255), nullable=True),
        sa.Column(u'certificate', sa.Text, nullable=False),
        sa.Column(u'passphrase', sa.String(128)),
        sa.Column(u'certificate_chain', sa.Text),
        sa.PrimaryKeyConstraint(u'id'),
    )
    op.create_table(
        u'ssltrustedcertificates',
        sa.Column(u'tenant_id', sa.String(255), nullable=True),
        sa.Column(u'id', sa.String(36), nullable=False),
        sa.Column(u'name', sa.String(255), nullable=True),
        sa.Column(u'description', sa.String(255), nullable=True),
        sa.Column(u'certificate', sa.Text, nullable=False),
        sa.PrimaryKeyConstraint(u'id'),
    )
    op.create_table(
        u'vipsslcertificateassociations',
        sa.Column(u'vip_id', sa.String(36), nullable=False),
        sa.Column(u'ssl_certificate_id', sa.String(36), nullable=False),
        sa.Column(u'status', sa.String(16), nullable=False),
        sa.Column(u'status_description', sa.String(255)),
        sa.ForeignKeyConstraint(['vip_id'], [u'vips.id'], ),
        sa.ForeignKeyConstraint(['ssl_certificate_id'],
                                [u'sslcertificates.id'], ),
        sa.PrimaryKeyConstraint(u'vip_id', u'ssl_certificate_id')
    )
    op.create_table(
        u'vipssltrustedcertificateassociations',
        sa.Column(u'vip_id', sa.String(36), nullable=False),
        sa.Column(u'ssl_trusted_certificate_id', sa.String(36),
                  nullable=False),
        sa.Column(u'status', sa.String(16), nullable=False),
        sa.Column(u'status_description', sa.String(255)),
        sa.ForeignKeyConstraint(['vip_id'], [u'vips.id'], ),
        sa.ForeignKeyConstraint(['ssl_trusted_certificate_id'],
                                [u'ssltrustedcertificates.id'], ),
        sa.PrimaryKeyConstraint(u'vip_id', u'ssl_trusted_certificate_id')
    )

    op.add_column('vips',
                  sa.Column(u'ssl_policy_id', sa.String(36),
                            sa.ForeignKey('sslpolicies.id',
                                          name='vip_ssl_policy_id_fk'),
                            nullable=True))

    # Create default SSL policy
    # TODO(Evgeny Fedoruk) insert default SSL policy


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('vipsslcertificateassociations')
    op.drop_table('vipssltrustedcertificateassociations')
    op.drop_table('sslcertificates')
    op.drop_table('ssltrustedcertificates')
    op.drop_constraint('vip_ssl_policy_id_fk', 'vips', type_='foreignkey')
    op.drop_column('vips', 'ssl_policy_id')
    op.drop_table('sslpolicies')
