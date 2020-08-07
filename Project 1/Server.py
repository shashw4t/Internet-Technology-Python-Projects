import socket 
import sys 
import binascii
import struct

def string_to_hex (url):
    ascii_list = [ord(a) for a in url]
    hex_list = [hex(a) for a in ascii_list]
    read_list = [str(a)[2:] for a in hex_list]

    if 'www.' in url: 
        read_list = read_list[4:]
        #print('url parsed)

    period = '2e'
    count = read_list.count(period)
    result = ""

    for x in range(0, count+1):
        if read_list.count(period) > 0:
            size = read_list.index(period)
            if size < 16:
                result = result +  '0' + str(hex(size))[2:] + ' '
            else:
                result = result + str(hex(size))[2:] + ' '
            for y in range(0, size):
                result = result + read_list[y] + ' '
            read_list = read_list[size+1:]
        else:
            size = len(read_list)
            if size < 16:
                result = result +  '0' + str(hex(size))[2:] + ' '
            else:
                result = result + str(hex(size))[2:] + ' '
            for z in range(0, size):
                result = result + read_list[z] + ' '
    
    return result

def hex_to_ip (response):
    cut = response[response.find('c00c'):]
    #print(cut)

    answers = int(response[15])
    #print(answers)
    if answers == 1: 
        if cut[20:24] != '0004':
            return ('not found')
        cut = cut[24:]
        #print(cut)
        #ip = int(cut, 16)
        #ip = socket.inet_ntoa(struct.pack("!L", ip))
        pairs = [cut[i:i+2] for i in range (0, len(cut), 2)]
        pairs = [int(i, 16) for i in pairs]
        ip = '.'.join(str(i) for i in pairs)
        return ip
    else: 
        multiple = ""
        for x in range(0, answers):
            if cut[20:24] != '0004':
                rdlength = cut[20:24]
                rdlength = int(rdlength, 16) * 2
                #print(rdlength)
                if multiple == "": 
                    multiple = multiple + 'not found'
                else:
                    multiple = multiple + ',not found'
                cut = cut[24 + rdlength:]
                #print(cut)
            else:
                #ip = cut[24:32]
                #ip = int(ip, 16)
                #ip = socket.inet_ntoa(struct.pack("!L", ip))
                cut2 = cut[24:32]
                pairs = [cut2[i:i+2] for i in range (0, len(cut2), 2)]
                pairs = [int(i, 16) for i in pairs]
                ip = '.'.join(str(i) for i in pairs)

                if multiple == "": 
                    multiple = multiple + str(ip)
                else:
                    multiple = multiple + ',' + str(ip)
                cut = cut[32:]
        return multiple

#https://stackoverflow.com/questions/2197974/convert-little-endian-hex-string-to-ip-address-in-python

port = int(sys.argv[1])
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('', port))
#print('bound to port ' + str(port))
server.listen(1)
client, addr = server.accept()

sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#udp socket to communicate to DNS 

header = "AA AA 01 00 00 01 00 00 00 00 00 00 "
end = "00 00 01 00 01"
dns = ("8.8.8.8", 53)

while 1:
    data = client.recv(256)
    if not data: break
    query = header + string_to_hex(data) + end
    query = query.replace(" ", "").replace("\n", "")

    sock2.sendto(binascii.unhexlify(query), dns)
    answer, addr2 = sock2.recvfrom(4096)
    response = binascii.hexlify(answer).decode("utf-8")
    client.sendall(hex_to_ip(response))
    

server.close()
sock2.close()

#some code used from 
#https://routley.io/posts/hand-writing-dns-messages/
#https://stackoverflow.com/questions/5619685/conversion-from-ip-string-to-integer-and-backward-in-python/16446104
