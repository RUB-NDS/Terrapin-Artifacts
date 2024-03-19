#!/usr/bin/env python3
# pyright: reportGeneralTypeIssues=false

"""
Server code from example of AsyncSSH, see:
https://asyncssh.readthedocs.io/en/stable/#server-examples

Modified to accept parameters from environment variables for easier integration with docker
"""
import click
import pathlib
import asyncio
import asyncssh
import logging
import sys

PASSWORDS = {}
AUTHORIZED_KEYS_FILES = {}


def handle_client(process: asyncssh.SSHServerProcess) -> None:
    process.stdout.write('Welcome to my SSH server, %s!\n' %
                         process.get_extra_info('username'))
    process.exit(0)


class MySSHServer(asyncssh.SSHServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._logger = logging.getLogger(__name__)
        self._conn = None

    def connection_made(self, conn):
        self._conn = conn
        self._logger.info("Connection established!")

    def begin_auth(self, username):
        assert self._conn is not None

        try:
            authorized_keys_file = AUTHORIZED_KEYS_FILES[username]
        except KeyError:
            self._logger.debug("User %r has no authorized_keys file.", username)
            self._logger.debug(
                "Users with authorized_keys file: %r.",
                list(AUTHORIZED_KEYS_FILES.keys()),
            )
            pass
        else:
            self._logger.debug(
                "authorized_keys file for user %r: %s", username, authorized_keys_file
            )
            try:
                self._conn.set_authorized_keys(str(authorized_keys_file))
            except IOError:
                self._logger.exception(
                    "error occurred during begin_auth, maybe there is no key for this user."
                )
                self._logger.debug(
                    "Falling back to password authentication for user %r.", username
                )
                pass
        return True

    def password_auth_supported(self):
        # If there are no passwords, let's password-authentication will be
        # disabled.
        return bool(PASSWORDS)

    def validate_password(self, username, password):
        self._logger.debug("Validating password for user %r.", username)
        try:
            expected_password = PASSWORDS[username]
        except KeyError:
            self._logger.debug("User %r has no password.", username)
            self._logger.debug("Users with passwords: %r.", list(PASSWORDS.keys()))
        else:
            if password == expected_password:
                self._logger.debug("Password for user %r is correct.", username)
                return True

        self._logger.debug("Password authentication for user %r failed.", username)
        return False


async def start_server(port, host_keys):
    await asyncssh.create_server(
        MySSHServer,
        "",
        port,
        server_host_keys=host_keys,
        process_factory=handle_client,
    )


def validate_username(ctx, param, value):
    stripped = value.strip()
    if not stripped:
        raise ValueError("Username must not be empty!")
    return stripped


@click.command()
@click.option(
    "-u", "--username", help="SSH username", type=str, callback=validate_username
)
@click.option(
    "-P",
    "--password",
    help="SSH password (password authentication will be disabled if not specified)",
    type=str,
)
@click.option(
    "-f",
    "--authorized-keys-file",
    help="SSH authorized_keys file (publickey authentication won't work if not specified)",
    type=pathlib.Path,
)
@click.option("-p", "--port", help="SSH port to listen on", default=22, type=int)
@click.option(
    "--host-key",
    help="SSH host key",
    default=pathlib.Path(__file__).parent.joinpath("ssh_host_rsa_key"),
    type=pathlib.Path,
)
def main(username, password, authorized_keys_file, port, host_key):
    logger = logging.getLogger(__name__)

    # Modification for AsyncSSH rogue session attack
    # Add an additional user "attacker" with password "attacker"
    PASSWORDS["attacker"] = "attacker"

    logger.info("Username: %r", username)
    if password is not None:
        logger.info("Password: %r", password)
        PASSWORDS[username] = password
    else:
        logger.warning("No password given, password auth will be disabled.")

    if authorized_keys_file is not None:
        logger.info("authorized_keys file: %s", authorized_keys_file)
        AUTHORIZED_KEYS_FILES[username] = authorized_keys_file
    else:
        logger.warning("No authorized_keys file given, publickey auth will not work.")

    if password is None and authorized_keys_file is None:
        logger.warning(
            "Neither password nor authorized_keys file specified, you won't be able to log in!"
        )

    logger.info("Server starting up on %d...", port)
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(start_server(port=port, host_keys=[host_key]))
    except (OSError, asyncssh.Error) as exc:
        sys.exit("Error starting server: " + str(exc))
    loop.run_forever()
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    asyncssh.set_log_level("DEBUG")
    asyncssh.set_debug_level(2)
    sys.exit(main(auto_envvar_prefix="SSH"))
