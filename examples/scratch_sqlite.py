"""Scratch Sqlite Auth Provider"""

import asyncio

from bareasgi_auth_server.auth_repository.password import Password
from bareasgi_auth_server.auth_repository.sqlite_authentication_repository import SqliteAuthenticationRepository
from bareasgi_auth_server.auth_repository.sqlite_authorization_repository import SqliteAuthorizationRepository
from bareasgi_auth_server.auth_repository import SqliteAuthRepository


async def play_async():
    provider = SqliteAuthenticationRepository("auth.db")
    await provider.initialise()

    pwd = Password(id=0, name='rob', salt='salt', hash='hash', state='active')
    await provider.create(pwd)
    print('done')

    pwd = Password(id=0, name='tom', salt='salt', hash='hash', state='active')
    await provider.create(pwd)
    print('done')

    try:
        pwd = await provider.read('foo')
        print(pwd)

        pwd = await provider.read('rob')
        print(pwd)

        pwd.hash = 'hsah'
        result = await provider.update(pwd)
        print(result)

        pwd.name = 'bor'
        result = await provider.update(pwd)
        print(result)

        result = await provider.delete(pwd.id)
        print(result)

        result = await provider.delete(pwd.id)
        print(result)

    except Exception as error:
        print(error)

async def init_async_old():
    authentication_repository = SqliteAuthenticationRepository("auth.db")
    await authentication_repository.initialise()

    if await authentication_repository.read('admin') is None:
        admin = await authentication_repository.create(Password.create('admin', 'trustno1', 'active'))
        print(admin.is_valid_password('trustno1'))
    if await authentication_repository.read('rtb') is None:
        rtb = await authentication_repository.create(Password.create('rtb', 'thereisnospoon', 'active'))
        print(rtb.is_valid_password('thereisnospoon'))

    authorization_repository = SqliteAuthorizationRepository("auth.db")
    await authorization_repository.initialise()
    for role in ('grant', 'revoke', 'read', 'write'):
        if not await authorization_repository.role_exists(role):
            await authorization_repository.add_role(role)

    for role in ('grant', 'revoke', 'read', 'write'):
        if not await authorization_repository.has_role('admin', role):
            await authorization_repository.grant('admin', role)

async def init_async():
    auth_repository = SqliteAuthRepository("auth.db")
    await auth_repository.initialise()
            

        
asyncio.run(init_async())