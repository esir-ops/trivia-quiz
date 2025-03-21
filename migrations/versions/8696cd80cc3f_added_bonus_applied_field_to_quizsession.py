"""Added bonus_applied field to QuizSession

Revision ID: 8696cd80cc3f
Revises: 03445a5db846
Create Date: 2025-03-20 13:54:12.240597

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8696cd80cc3f'
down_revision = '03445a5db846'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('quiz_session', schema=None) as batch_op:
        batch_op.add_column(sa.Column('bonus_applied', sa.Boolean(), nullable=True))

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('is_admin')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_admin', sa.BOOLEAN(), nullable=True))

    with op.batch_alter_table('quiz_session', schema=None) as batch_op:
        batch_op.drop_column('bonus_applied')

    # ### end Alembic commands ###
