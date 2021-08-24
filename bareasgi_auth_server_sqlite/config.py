"""Configuration"""

from __future__ import annotations

from datetime import timedelta
import io
from os.path import expanduser, expandvars
from typing import Any, Dict, Optional, TextIO, Union

import yaml

from .utils import parse_duration


def _expand_path(path: Optional[str]) -> Optional[str]:
    return None if path is None else expanduser(path)


def _expandobjvars(obj: Any) -> Any:
    if isinstance(obj, str):
        return expandvars(obj)

    if isinstance(obj, list):
        return [
            _expandobjvars(item)
            for item in obj
        ]

    if isinstance(obj, dict):
        return {
            key: _expandobjvars(value)
            for key, value in obj.items()
        }

    return obj


class TlsConfig:

    def __init__(
            self,
            is_enabled: bool,
            certfile: Optional[str],
            keyfile: Optional[str]
    ) -> None:
        self.is_enabled = is_enabled
        self.certfile = certfile
        self.keyfile = keyfile

    @classmethod
    def create(cls, dct: Dict[str, Any]) -> TlsConfig:
        return TlsConfig(
            dct['is_enabled'] == 'true',
            dct.get('certfile'),
            dct.get('keyfile')
        )


class AppConfig:

    def __init__(
            self,
            host: str,
            port: int,
            tls: Optional[TlsConfig],
            path_prefix: str
    ) -> None:
        self.host = host
        self.port = port
        self.tls = tls
        self.path_prefix = path_prefix

    @classmethod
    def create(cls, dct: Dict[str, Any]) -> AppConfig:
        return AppConfig(
            dct['host'],
            int(dct['port']),
            TlsConfig.create(dct['tls']) if 'tls' in dct else None,
            dct['path_prefix']
        )


class CookieConfig:

    def __init__(
            self,
            name: str,
            domain: str,
            path: str,
            expiry: timedelta,
    ) -> None:
        self.name = name
        self.domain = domain
        self.path = path
        self.expiry = expiry

    @classmethod
    def create(cls, dct: Dict[str, Any]) -> CookieConfig:
        return CookieConfig(
            dct['name'],
            dct['domain'],
            dct['path'],
            parse_duration(dct['expiry'])
        )


class JwtConfig:

    def __init__(
            self,
            secret: str,
            issuer: str,
            expiry: timedelta
    ) -> None:
        self.secret = secret
        self.issuer = issuer
        self.expiry = expiry

    @classmethod
    def create(cls, dct: Dict[str, Any]) -> JwtConfig:
        return JwtConfig(
            dct['secret'],
            dct['issuer'],
            parse_duration(dct['expiry'])
        )


class SqlConfig:

    def __init__(
            self,
            url: str
    ) -> None:
        self.url = url

    @classmethod
    def create(cls, dct: Dict[str, Any]) -> SqlConfig:
        return SqlConfig(
            dct['url']
        )


class Config:

    def __init__(
            self,
            app: AppConfig,
            cookie: CookieConfig,
            jwt: JwtConfig,
            sql: SqlConfig,
            log: Optional[Dict[str, Any]]
    ) -> None:
        self.app = app
        self.cookie = cookie
        self.jwt = jwt
        self.sql = sql
        self.log = log

    @classmethod
    def create(cls, dct: Dict[str, Any]) -> Config:
        return Config(
            AppConfig.create(dct['app']),
            CookieConfig.create(dct['cookie']),
            JwtConfig.create(dct['jwt']),
            SqlConfig.create(dct['sql']),
            dct.get('log')
        )

    @classmethod
    def load(cls, fp: Union[str, TextIO]) -> Config:
        if isinstance(fp, str):
            with open(fp, 'rt') as file_ptr:
                return cls.load(file_ptr)
        elif isinstance(fp, io.TextIOBase):
            dct = yaml.load(fp, Loader=yaml.FullLoader)
            return cls.create(_expandobjvars(dct))
        else:
            raise ValueError("Expected a file like object")
