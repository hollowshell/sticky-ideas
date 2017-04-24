# TCP Client Creation
import socket
import sys

target_host = "www.google.com"
target_port = 80
data = " ".join(sys.argv[1:])

# create socket object
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    # connect to server & send
    sock.connect((target_host, target_port))
    sock.sendall(bytes(data + "\n", "utf-8"))

    # receive data from server & shut down
    received = str(sock.recv(1024), "utf-8")

print("Sent:    {}".format(data))
print(data)
print("Received: {}".format(received))

