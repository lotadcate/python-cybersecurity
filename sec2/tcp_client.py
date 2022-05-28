import socket

target_host = "0.0.0.0"
target_port = 9997

# client
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect to server
client.connect((target_host, target_port))

client.send(b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")
response = client.recv(4096)

print(response.decode())
client.close()