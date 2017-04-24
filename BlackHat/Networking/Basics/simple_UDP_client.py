# UDP Client Creation
import socket
import sys

target_host = "127.0.0.1"
target_port = 80
data = " ".join(sys.argv[1:])

# create a socket object
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    # connect to server & send
    sock.connect((target_host, target_port))
    sock.sendall(bytes(data + "\n", "utf-8"))

    # receive data from server & stop
    receive, addr = str(sock.recvfrom(1024))

print(receive)