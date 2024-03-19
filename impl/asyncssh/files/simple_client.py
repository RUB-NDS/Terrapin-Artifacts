#!/usr/bin/env python
# pyright: reportGeneralTypeIssues=false

import click
import asyncio
import asyncssh
import sys
import logging

@click.command()
@click.option("-H", "--host", help="hostname or ip", default='127.0.0.1')
@click.option("-p", "--port", help="port", default=22, type=int)
@click.option("-u", "--username", help="username", default="victim")
@click.option("-P", "--password", help="password", default="secret")
@click.option("-c", "--command", help="command", default="pwd")
@click.option(
    "-o",
    "--output",
    is_flag=True,
    show_default=True,
    default=False,
    help="print output",
)
@click.option(
    "-e", "--error", is_flag=True, show_default=True, default=False, help="print error"
)
def client_start(host, port, username, password, command, output, error):
    print(f"Connecting to {host}:{port} as {username}")

    try:
        asyncio.get_event_loop().run_until_complete(
            run_client(host, port, username, password, command, output, error)
        )
    except (OSError, asyncssh.Error) as exc:
        sys.exit("SSH connection failed: " + str(exc))


async def run_client(host, port, username, password, command, output, error):
    async with asyncssh.connect(
        host=host, port=port, username=username, password=password, known_hosts="/root/.ssh/known_hosts", compression_algs=None
    ) as conn:
        result = await conn.run(command, check=True)
        print(result.stdout, end="")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    asyncssh.set_log_level("DEBUG")
    asyncssh.set_debug_level(2)
    client_start()
