"""Entrypoint for starting the server"""

import asyncio
import logging
import sys
from bareasgi_auth_server_sqlite import start_server


def main():
    """Main entry point"""
    asyncio.run(start_server(sys.argv))
    logging.shutdown()


if __name__ == "__main__":
    main()
