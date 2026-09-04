"""add scan_depth column to scan_jobs

Records whether a scan was run as 'fast' (passive only) or 'deep' (includes the
Active Recon & Fuzzing phase), so past scans can be distinguished in history.

Revision ID: 0001_add_scan_depth
Revises:
Create Date: 2026-08-24

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


# revision identifiers, used by Alembic.
revision = "0001_add_scan_depth"
down_revision = None
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    """True if `column` already exists on `table` (idempotency guard)."""
    bind = op.get_bind()
    return column in {c["name"] for c in inspect(bind).get_columns(table)}


def upgrade() -> None:
    # Idempotent: the app's runtime schema top-up (app._ensure_schema) may have
    # already added this column, so skip it here rather than failing with a
    # duplicate-column error. batch_alter_table keeps this portable on SQLite.
    if _has_column("scan_jobs", "scan_depth"):
        return
    with op.batch_alter_table("scan_jobs", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("scan_depth", sa.String(length=4),
                      nullable=True, server_default="fast")
        )


def downgrade() -> None:
    if not _has_column("scan_jobs", "scan_depth"):
        return
    with op.batch_alter_table("scan_jobs", schema=None) as batch_op:
        batch_op.drop_column("scan_depth")
