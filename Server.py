import socket 
import sys 

port = int(sys.argv[1])
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('', port))
#print('bound to port ' + str(port))
server.listen(1)

client, addr = server.accept()

while 1:
    data = client.recv(256)
    if not data: break
    reverse = data[::-1]
    client.sendall(reverse)

#print('data sent')
server.close()