"""Store role assignments on users as a JSONB list.

Roles live on the account row rather than in a join table: the set is small,
it is always read together with the user, and it is copied verbatim into the
access token. Existing accounts are backfilled with the baseline role so no
row is left without a role.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "003_add_user_roles"
down_revision = "002_add_tenants"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "roles",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[\"user\"]'::jsonb"),
        ),
    )
    # The server default only covers rows inserted from now on; make the
    # backfill explicit so an older row is never read as having no roles.
    op.execute(
        "UPDATE users SET roles = '[\"user\"]'::jsonb "
        "WHERE roles IS NULL OR roles = '[]'::jsonb"
    )
    # Containment lookups ("does this user hold admin?") stay cheap.
    op.create_index(
        "ix_users_roles",
        "users",
        ["roles"],
        postgresql_using="gin",
    )


def downgrade() -> None:
    op.drop_index("ix_users_roles", table_name="users")
    op.drop_column("users", "roles")
