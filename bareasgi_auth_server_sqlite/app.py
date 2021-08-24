"""
Application
"""

from bareasgi import Application
from bareasgi_cors import CORSMiddleware
from bareasgi_auth_common import TokenManager
from bareasgi_auth_server import AuthController
from .sql_auth_service import SqlAuthService
from .config import Config


def make_application(config: Config) -> Application:

    cors_middleware = CORSMiddleware()

    app = Application(middlewares=[cors_middleware])

    auth_service = SqlAuthService(
        config.sql.url
    )
    token_manager = TokenManager(
        config.jwt.secret,
        config.cookie.expiry,
        config.jwt.issuer,
        config.cookie.name,
        config.cookie.domain,
        config.cookie.path,
        config.jwt.expiry
    )

    auth_controller = AuthController(
        config.app.path_prefix,
        token_manager,
        auth_service,
    )

    auth_controller.add_routes(app)

    return app
