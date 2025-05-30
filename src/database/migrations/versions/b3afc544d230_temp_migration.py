"""temp_migration

Revision ID: b3afc544d230
Revises: b92c2f4b92a5
Create Date: 2025-03-26 09:16:54.669263

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b3afc544d230"
down_revision: Union[str, None] = "b92c2f4b92a5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column("movies", sa.Column("rate_count", sa.Integer(), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column("movies", "rate_count")
    # ### end Alembic commands ###
