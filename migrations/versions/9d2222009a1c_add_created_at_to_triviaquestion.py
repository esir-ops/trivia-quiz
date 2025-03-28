"""Add created_at to TriviaQuestion

Revision ID: 9d2222009a1c
Revises: 4f9ea4d73b53
Create Date: 2025-03-20 20:18:02.094793

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9d2222009a1c'
down_revision = '4f9ea4d73b53'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('trivia_question', schema=None) as batch_op:
        batch_op.add_column(sa.Column('created_at', sa.DateTime(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('trivia_question', schema=None) as batch_op:
        batch_op.drop_column('created_at')

    # ### end Alembic commands ###
