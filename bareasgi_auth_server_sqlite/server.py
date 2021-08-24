"""
Server
"""

import argparse
import logging
import logging.config

from bareasgi import Application
from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig

from .app import make_application
from .config import Config

LOGGER = logging.getLogger(__name__)


async def _start_http_server(app: Application, config: Config) -> None:
    """Start the hypercorn ASGI server"""

    web_config = HypercornConfig()
    web_config.bind = [f'{config.app.host}:{config.app.port}']

    if config.app.tls is not None and config.app.tls.is_enabled:
        web_config.keyfile = config.app.tls.keyfile
        web_config.certfile = config.app.tls.certfile

    await serve(
        app,  # type: ignore
        web_config
    )


def _initialise_logging(config: Config) -> None:
    if config.log is not None:
        logging.config.dictConfig(config.log)


def _parse_args(argv: list):
    """Parse the command line args"""
    parser = argparse.ArgumentParser(
        description='Order File Service',
        add_help=False)

    parser.add_argument(
        '--help', help='Show usage',
        action='help')
    parser.add_argument(
        '-f', '--config-file', help='Path to the configuration file.',
        action="store", dest='CONFIG_FILE')

    return parser.parse_args(argv)


async def start_server(argv: list) -> None:
    args = _parse_args(argv[1:])
    config = Config.load(args.CONFIG_FILE)
    app = make_application(config)
    await _start_http_server(app, config)
    logging.shutdown()
