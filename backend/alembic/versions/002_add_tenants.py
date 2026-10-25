"""Add tenant ownership constraints to authentication tables."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "002_add_tenants"
down_revision = "001_initial_auth"
branch_labels = None
depends_on = None

DEFAULT_TENANT_ID = "550e8400-e29b-41d4-a716-446655440000"


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("slug", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.execute(
        "INSERT INTO tenants (id, slug, name, is_active) "
        f"VALUES ('{DEFAULT_TENANT_ID}', 'default', 'Default Tenant', true) "
        "ON CONFLICT (id) DO NOTHING"
    )
    for table_name in ("users", "refresh_tokens", "email_verification_tokens"):
        op.execute(
            "INSERT INTO tenants (id, slug, name, is_active) "
            "SELECT DISTINCT tenant_id, 'tenant-' || replace(tenant_id::text, '-', ''), "
            f"'Migrated Tenant', true FROM {table_name} "
            f"WHERE tenant_id <> '{DEFAULT_TENANT_ID}' "
            "ON CONFLICT (id) DO NOTHING"
        )
    for table_name in ("users", "refresh_tokens", "email_verification_tokens"):
        op.execute(
            f"UPDATE {table_name} SET tenant_id = '{DEFAULT_TENANT_ID}' "
            "WHERE tenant_id IS NULL"
        )
        op.create_foreign_key(
            f"fk_{table_name}_tenant_id", table_name, "tenants", ["tenant_id"], ["id"], ondelete="RESTRICT"
        )


def downgrade() -> None:
    for table_name in ("email_verification_tokens", "refresh_tokens", "users"):
        op.drop_constraint(f"fk_{table_name}_tenant_id", table_name, type_="foreignkey")
    op.drop_table("tenants")
