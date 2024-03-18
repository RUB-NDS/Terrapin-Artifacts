from threading import Thread
import socket

newkeys_payload = b'\x00\x00\x00\x0c\x0a\x15'
def contains_newkeys(data):
    return newkeys_payload in data

def pipe_socket_stream(in_socket, out_socket):
    try:
        while True:
            data = in_socket.recv(4096)
            if len(data) == 0:
                break
            out_socket.send(data)
    except ConnectionResetError:
        print("[!] Socket connection has been reset. Closing sockets.", flush=True)
    except OSError:
        print("[!] Sockets closed by another thread. Terminating pipe_socket_stream thread.", flush=True)
    in_socket.close()
    out_socket.close()

def run_tcp_mitm(proxy_ip, proxy_port, server_ip, server_port, forward_client_to_server = pipe_socket_stream, forward_server_to_client = pipe_socket_stream):
    mitm_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mitm_socket.bind((proxy_ip, proxy_port))
    mitm_socket.listen(5)

    print(f"[+] MitM Proxy started. Listening on {(proxy_ip, proxy_port)} for incoming connections...", flush=True)
    try:
        while True:
            client_socket, client_addr = mitm_socket.accept()
            print(f"[+] Accepted connection from: {client_addr}", flush=True)
            print(f"[+] Establishing new target connection to {(server_ip, server_port)}.", flush=True)
            # Establish a new connection to the target and 
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((server_ip, server_port))
            print("[+] Spawning new forwarding threads to handle client connection.", flush=True)
            forward_client_to_server_thread = Thread(target=forward_client_to_server, args=(client_socket, server_socket), daemon=True)
            forward_client_to_server_thread.start()
            forward_server_to_client_thread = Thread(target=forward_server_to_client, args=(server_socket, client_socket), daemon=True)
            forward_server_to_client_thread.start()
    except KeyboardInterrupt:
        client_socket.close()
        server_socket.close()
        mitm_socket.close()
