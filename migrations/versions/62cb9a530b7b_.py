"""empty message

Revision ID: 62cb9a530b7b
Revises: 
Create Date: 2019-01-08 11:52:49.490909

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '62cb9a530b7b'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('tbl_revoked_token',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('jti', sa.String(length=120), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('tbl_user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=80), nullable=False),
    sa.Column('password', sa.String(length=100), nullable=False),
    sa.Column('status', sa.String(length=80), nullable=False),
    sa.Column('record_date', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_update', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('password'),
    sa.UniqueConstraint('status'),
    sa.UniqueConstraint('username')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('tbl_user')
    op.drop_table('tbl_revoked_token')
    # ### end Alembic commands ###
