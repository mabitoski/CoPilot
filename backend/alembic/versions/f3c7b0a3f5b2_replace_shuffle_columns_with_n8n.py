"""Rename Shuffle columns to N8N equivalents

Revision ID: f3c7b0a3f5b2
Revises: aae5e3008a35
Create Date: 2024-08-30 12:00:00.000000

"""
from typing import Sequence
from typing import Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "f3c7b0a3f5b2"
down_revision: Union[str, None] = "d8f9e9ea5502"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "alert_creation_settings",
        "shuffle_endpoint",
        new_column_name="n8n_endpoint",
        existing_type=sa.String(length=1024),
        existing_nullable=True,
    )
    op.alter_column(
        "incident_management_notification",
        "shuffle_workflow_id",
        new_column_name="n8n_workflow_id",
        existing_type=sa.String(length=1000),
        existing_nullable=False,
    )
    op.execute(
        sa.text("UPDATE connectors SET connector_name = 'N8N' WHERE connector_name = 'Shuffle'")
    )


def downgrade() -> None:
    op.alter_column(
        "incident_management_notification",
        "n8n_workflow_id",
        new_column_name="shuffle_workflow_id",
        existing_type=sa.String(length=1000),
        existing_nullable=False,
    )
    op.alter_column(
        "alert_creation_settings",
        "n8n_endpoint",
        new_column_name="shuffle_endpoint",
        existing_type=sa.String(length=1024),
        existing_nullable=True,
    )
    op.execute(
        sa.text("UPDATE connectors SET connector_name = 'Shuffle' WHERE connector_name = 'N8N'")
    )
