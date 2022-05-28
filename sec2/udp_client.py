import socket

target_host = "127.0.0.1"
target_port = 9997

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.sendto(b"AAABBBCCC", (target_host, target_port))

data, address = client.recvfrom(4096)

print(data.decode('utf-8'))
print(address)

client.close()