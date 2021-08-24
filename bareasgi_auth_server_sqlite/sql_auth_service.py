"""A SQL Auth Provider"""

import hashlib
from typing import AbstractSet, Dict, Mapping, Optional, Set, Tuple
import uuid

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from bareasgi_auth_server.auth_service import AuthService


class SqlAuthService(AuthService):
    """SQL Auth Provider"""

    def __init__(self, url: str) -> None:
        self._engine = create_async_engine(url)
        self._users: Optional[sa.Table] = None
        self._roles: Optional[sa.Table] = None
        self._members: Optional[sa.Table] = None

    async def authenticate(self, **credentials) -> Optional[str]:
        username = credentials['username']
        password = credentials['password']

        try:
            if await self.check_password(username, password):
                return username

        except:  # pylint: disable=bare-except
            pass

        return None

    async def is_valid_user(self, user: str) -> bool:
        return await self.user_is_enabled(user)

    async def authorizations(self, user: str) -> AbstractSet[str]:
        return await self.user_roles(user)

    async def add_user(self, name: str, password: str, is_enabled: bool) -> bool:
        assert self._users is not None, "repository not initialised"

        salt, hashed_password = self._hash_password(password)

        stmt = self._users.insert([{
            'name': name,
            'salt': salt,
            'hashed_password': hashed_password,
            'is_enabled': is_enabled
        }])

        try:
            async with self._engine.begin() as conn:
                await conn.execute(stmt)

            return True

        except sa.exc.IntegrityError:
            return False

    async def user_exists(self, name: str) -> bool:
        assert self._users is not None, "repository not initialised"

        stmt = sa.select(
            self._users.c.user_id
        ).where(
            self._users.c.name == name
        )

        async with self._engine.connect() as conn:
            cursor = await conn.stream(stmt)
            row = await cursor.fetchone()
            return row is not None

    async def user_is_enabled(self, name: str) -> bool:
        assert self._users is not None, "repository not initialised"

        stmt = sa.select(
            self._users.c.is_enabled
        ).where(
            self._users.c.name == name
        )

        async with self._engine.connect() as conn:
            cursor = await conn.stream(stmt)
            row = await cursor.fetchone()
            return row is not None and row['is_enabled']

    async def check_password(self, name: str, password: str) -> bool:
        assert self._users is not None, "repository not initialised"

        stmt = sa.select(
            self._users.c.salt,
            self._users.c.hashed_password
        ).where(
            self._users.c.name == name
        )

        async with self._engine.connect() as conn:
            cursor = await conn.stream(stmt)
            row = await cursor.fetchone()
            return row is not None and self._is_valid_password(
                password,
                row['salt'],
                row['hashed_password']
            )

    async def change_password(self, name: str, password: str) -> bool:
        assert self._users is not None, "repository not initialised"

        salt, hashed_password = self._hash_password(password)

        stmt = self._users.update().values({
            self._users.c.salt: salt,
            self._users.c.hashed_password: hashed_password
        }).where(
            self._users.c.name == name
        )

        async with self._engine.begin() as conn:
            result = await conn.execute(stmt)
            return result.rowcount == 1

    async def delete_user(self, name: str) -> bool:
        assert self._users is not None, "repository not initialised"

        stmt = self._users.delete().where(
            self._users.c.name == name
        )

        async with self._engine.begin() as conn:
            result = await conn.execute(stmt)
            return result.rowcount == 1

    async def add_role(self, name: str, description: Optional[str] = None) -> bool:
        assert self._roles is not None, "repository not initialised"
        stmt = self._roles.insert([{
            self._roles.c.name: name,
            self._roles.c.description: description,
        }])
        try:
            async with self._engine.begin() as conn:
                await conn.execute(stmt)
            return True
        except sa.exc.IntegrityError:
            return False

    async def delete_role(self, name: str) -> bool:
        assert self._roles is not None, "repository not initialised"
        stmt = self._roles.delete().where(self._roles.c.name == name)
        async with self._engine.begin() as conn:
            result = await conn.execute(stmt)
            return result.rowcount == 1

    async def has_role(self, user: str, group: str) -> bool:
        assert self._users is not None, "repository not initialised"
        assert self._roles is not None, "repository not initialised"
        assert self._members is not None, "repository not initialised"
        stmt = sa.select(
            self._members.c.member_id
        ).join(
            self._users,
            sa.and_(
                self._users.c.name == user,
                self._users.c.user_id == self._members.c.user_id
            )
        ).join(
            self._roles,
            sa.and_(
                self._roles.c.name == group,
                self._roles.c.role_id == self._members.c.role_id
            )
        )
        async with self._engine.connect() as conn:
            cursor = await conn.stream(stmt)
            row = await cursor.fetchone()
            return row is not None

    async def role_exists(self, group: str) -> bool:
        assert self._roles is not None, "repository not initialised"
        stmt = sa.select(
            self._roles.c.role_id
        ).where(
            self._roles.c.name == group
        )
        async with self._engine.connect() as conn:
            cursor = await conn.stream(stmt)
            row = await cursor.fetchone()
            return row is not None

    async def grant(self, user: str, role: str) -> bool:
        assert self._users is not None, "repository not initialised"
        assert self._roles is not None, "repository not initialised"
        assert self._members is not None, "repository not initialised"
        stmt = self._members.insert().from_select(
            [
                self._users.c.user_id,
                self._roles.c.role_id
            ],
            sa.select(
                self._users.c.user_id,
                self._roles.c.role_id
            ).select_from(
                self._users,
                self._roles
            ).where(
                sa.and_(
                    self._users.c.name == user,
                    self._roles.c.name == role
                )
            )
        )
        async with self._engine.begin() as conn:
            result = await conn.execute(stmt)
            return result.rowcount == 1

    async def revoke(self, user: str, role: str) -> bool:
        assert self._users is not None, "repository not initialised"
        assert self._roles is not None, "repository not initialised"
        assert self._members is not None, "repository not initialised"
        stmt = self._members.delete().where(
            sa.exists(
                sa.select(
                    self._members.c.id
                ).select_from(
                    self._members
                ).join(
                    self._users,
                    sa.and_(
                        self._users.c.user_id == self._members.c.user_id,
                        self._users.c.name == user
                    )
                ).join(
                    self._roles,
                    sa.and_(
                        self._roles.c.role_id == self._members.c.member_id,
                        self._roles.c.name == role
                    )
                )
            )
        )
        async with self._engine.begin() as conn:
            result = await conn.execute(stmt)
            return result.rowcount == 1

    async def role_users(self, role: str) -> AbstractSet[str]:
        assert self._users is not None, "repository not initialised"
        assert self._roles is not None, "repository not initialised"
        assert self._members is not None, "repository not initialised"
        stmt = sa.select(
            self._users.c.name
        ).join(
            self._members,
            self._members.c.user_id == self._users.c.user_id
        ).join(
            self._roles,
            sa.and_(
                self._roles.c.role_id == self._members.c.role_id,
                self._roles.c.name == role
            )
        )
        async with self._engine.connect() as conn:
            cursor = await conn.stream(stmt)
            return {row['name'] async for row in cursor}

    async def user_roles(self, user: str) -> AbstractSet[str]:
        assert self._users is not None, "repository not initialised"
        assert self._roles is not None, "repository not initialised"
        assert self._members is not None, "repository not initialised"
        stmt = sa.select(
            self._roles.c.name
        ).join(
            self._members,
            self._members.c.role_id == self._roles.c.role_id
        ).join(
            self._users,
            self._users.c.user_id == self._members.c.user_id
        ).where(
            self._users.c.name == user
        )
        async with self._engine.connect() as conn:
            cursor = await conn.stream(stmt)
            return {row['name'] async for row in cursor}

    async def update_user_roles(self, user: str, roles: AbstractSet[str]) -> bool:
        assert self._users is not None, "repository not initialised"
        assert self._roles is not None, "repository not initialised"
        assert self._members is not None, "repository not initialised"
        stmt = self._members.delete().where(
            sa.exists(
                sa.select(
                    self._members.c.member_id
                ).join(
                    self._users,
                    self._users.c.user_id == self._members.c.member_id
                ).where(
                    self._users.c.name == user
                )
            )
        )
        async with self._engine.begin() as conn:
            await conn.execute(stmt)
            result = await conn.execute(
                self._members.insert().select_from(
                    sa.select(
                        self._users.c.user_id,
                        self._roles.c.role_id
                    ).where(
                        sa.and_(
                            self._users.c.name == user,
                            self._roles.c.name.in_(roles)
                        )
                    )
                )
            )
            return result.rowcount > 0

    async def permissions(self, roles_by_users: bool) -> Mapping[str, AbstractSet[str]]:
        assert self._users is not None, "repository not initialised"
        assert self._roles is not None, "repository not initialised"
        assert self._members is not None, "repository not initialised"
        stmt = sa.select(
            self._users.c.name.label('user_name'),
            self._roles.c.name.label('role_name')
        ).join(
            self._members,
            self._members.c.role_id == self._roles.c.role_id
        ).join(
            self._users,
            self._users.c.user_id == self._members.c.user_id
        )
        async with self._engine.connect() as conn:
            cursor = await conn.stream(stmt)
            dct: Dict[str, Set[str]] = {}
            if roles_by_users:
                key = 'user_name'
                value = 'role_name'
            else:
                key = 'role_name'
                value = 'user_name'

            async for row in cursor:
                if row[key] not in dct:
                    dct[row[key]] = {row[value]}
                else:
                    dct[row[key]].add(row[value])

            return dct

    async def open(self) -> None:

        metadata = sa.MetaData(bind=self._engine)

        async with self._engine.begin() as conn:
            await conn.run_sync(metadata.reflect)

            is_dirty = False

            if 'users' in metadata.tables:
                self._users = metadata.tables['users']
            else:
                is_dirty = True
                self._users = self._define_users_table(metadata)

            if 'roles' in metadata.tables:
                self._roles = metadata.tables['roles']
            else:
                is_dirty = True
                self._roles = self._define_roles_table(metadata)

            if 'members' in metadata.tables:
                self._members = metadata.tables['members']
            else:
                is_dirty = True
                self._members = self._define_members_table(metadata)

            if is_dirty:
                await conn.run_sync(metadata.create_all)

            if await self.user_exists('admin'):
                await self.add_user('admin', 'admin', True)

    @classmethod
    def _define_users_table(cls, metadata: sa.MetaData) -> sa.Table:
        return sa.Table(
            'users',
            metadata,
            sa.Column(
                'user_id',
                sa.Integer,
                nullable=False,
                primary_key=True,
                autoincrement=True
            ),
            sa.Column(
                'name',
                sa.String(256),
                nullable=False
            ),
            sa.Column(
                'salt',
                sa.CHAR(32),
                nullable=False
            ),
            sa.Column(
                'hashed_password',
                sa.String(128),
                nullable=False
            ),
            sa.Column(
                'is_enabled',
                sa.Boolean,
                nullable=False
            ),
            sa.UniqueConstraint('name'),
            # schema='auth'
        )

    @classmethod
    def _define_roles_table(cls, metadata: sa.MetaData) -> sa.Table:
        return sa.Table(
            'roles',
            metadata,
            sa.Column(
                'role_id',
                sa.Integer,
                nullable=False,
                primary_key=True,
                autoincrement=True
            ),
            sa.Column(
                'name',
                sa.String(256),
                nullable=False
            ),
            sa.Column(
                'description',
                sa.String(128),
                nullable=True
            ),
            sa.UniqueConstraint('name'),

        )

    @classmethod
    def _define_members_table(cls, metadata: sa.MetaData) -> sa.Table:
        return sa.Table(
            'members',
            metadata,
            sa.Column(
                'member_id',
                sa.Integer,
                nullable=False,
                primary_key=True,
                autoincrement=True
            ),
            sa.Column(
                'user_id',
                sa.Integer,
                nullable=False
            ),
            sa.Column(
                'role_id',
                sa.Integer,
                nullable=False
            ),
            sa.UniqueConstraint('user_id', 'role_id'),
            sa.ForeignKeyConstraint(['user_id'], ['users.user_id']),
            sa.ForeignKeyConstraint(['role_id'], ['roles.role_id']),
        )

    @classmethod
    def _is_valid_password(
            cls,
            password: str,
            salt: str,
            hashed_password: str
    ) -> bool:
        check_hashed_password = hashlib.sha512(
            (password + salt).encode()
        ).hexdigest()
        return hashed_password == check_hashed_password

    @classmethod
    def _hash_password(cls, password: str) -> Tuple[str, str]:
        salt = uuid.uuid4().hex
        hashed_password = hashlib.sha512(
            (password + salt).encode()
        ).hexdigest()
        return salt, hashed_password
