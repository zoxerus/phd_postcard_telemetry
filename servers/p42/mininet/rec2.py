import socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
s.bind(('0.0.0.0', 54321))
print(' 1 ')
while True:
    print( s.recvfrom(65535) )