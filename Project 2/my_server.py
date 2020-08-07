#Abraham Gale 2020
#feel free to add functions to this part of the project, just make sure that the get_dns_response function works
from resolver_backround import DnsResolver
import threading
import socket
import struct
import argparse
from sys import argv
from time import sleep
from helper_funcs import DNSQuery
import binascii

sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
cache = {}

class MyResolver(DnsResolver):
	def __init__(self, port):
		self.port = port
		#define variables and locks you will need here
		self.cache_lock = threading.Lock()
		
	def get_dns_response(self, query):
		#input: A query and any state in self
		#returns: the correct response to the query obtained by asking DNS name servers
		#Your code goes here, when you change any 'self' variables make sure to use a lock
		q = DNSQuery(query)
		#print(q)
		#print(q.question['NAME'])
		global sock2
		global cache
		SBELT = ['128.6.1.1', '172.16.7.7', '198.41.0.4']
		#SLIST = []
		a = DNSQuery()
		#step 1 check if answer is in cache 
		if q.question['NAME'].decode() in cache:
			#print(cache[q.question['NAME'].decode()])
			print(q)
			print('\nAnswer Section')
			print(q.question['NAME'].decode() + '             ' + hex_to_ip(binascii.hexlify(q.to_bytes()).decode("utf-8")))
			return

		else: 
			#Step 2 find best servers to ask 
			domain = q.question['NAME'].decode()
			#check each snippet of the url to find optimal name servers
			for x in range(0, domain.count('.')):
				if domain in cache and "'TYPE': 2" in cache[domain].answers:
					nsip = hex_to_ip(binascii.hexlify(cache[domain].to_bytes()).decode("utf-8"))
					sock2.sendto(q.to_bytes(), (nsip, 53))
					answer, addr2 = sock2.recvfrom(4096)
					a = DNSQuery(answer)
					print(a)
					print('\nAnswer Section')
					print(a.question['NAME'].decode() + '             ' + hex_to_ip(binascii.hexlify(a.to_bytes()).decode("utf-8")))
					return
				domain = domain[domain.index('.') + 1:]

			#check SLIST for something and check those 

			#Step 3 Query until response 
			#querying SBELT servers if no matches in SLIST
			sock2.settimeout(5)
			for x in range(0, len(SBELT)):
				sock2.sendto(q.to_bytes(), (SBELT[x], 53))
				flag = 1
				try:
					answer, addr2 = sock2.recvfrom(4096)	
					if answer:
						a = DNSQuery(answer)
						flag = 333
				except socket.timeout: 
					print('timeout')
				if flag == 333:
					break

			#Step 4 cache the data and print results
			self.update_cache(a)
			#cache[a.question['NAME'].decode()] = a
			#print(cache['facebook.com.'])

			#check if the type is a host address, NS, or cname
			num = 2
			#this logic wasn't working properly, so I disabled it
			while num == 1:
				if "'TYPE': 1" in cache[a.question['NAME'].decode()].answers:
					num = 1	
				elif "'TYPE': 2" in cache[a.question['NAME'].decode()].answers:
					nsip = hex_to_ip(binascii.hexlify(cache[a.question['NAME'].decode()].to_bytes()).decode("utf-8"))
					sock2.sendto(q.to_bytes(), (nsip, 53))
					answer, addr2 = sock2.recvfrom(4096)
					a = DNSQuery(answer)
				elif "'TYPE': 5" in cache[a.question['NAME'].decode()].answers:
					cname = hex_to_ip(binascii.hexlify(cache[a.question['NAME'].decode()].to_bytes()).decode("utf-8"))
					q.question['NAME'] = cname
					sock2.sendto(q.to_bytes(), ('8.8.8.8', 53))
					answer, addr2 = sock2.recvfrom(4096)
					a = DNSQuery(answer)

			print(a)
			print('\nAnswer Section')
			print(a.question['NAME'].decode() + '             ' + hex_to_ip(binascii.hexlify(a.to_bytes()).decode("utf-8")))


			#print(a.answers)
		return a.to_bytes()

	def update_cache(self, name):
		global cache
		with self.cache_lock:
			cache[name.question['NAME'].decode()] = name	
		return 


def hex_to_ip (response):
    cut = response[response.find('c00c'):]

    answers = int(response[15])

    if answers == 1: 
        if cut[20:24] != '0004':
            return ('not found')
        cut = cut[24:]

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

                if multiple == "": 
                    multiple = multiple + 'not found'
                else:
                    multiple = multiple + ',not found'
                cut = cut[24 + rdlength:]

            else:

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


parser = argparse.ArgumentParser(description="""This is a DNS resolver""")
parser.add_argument('port', type=int, help='This is the port to connect to the resolver on',action='store')
args = parser.parse_args(argv[1:])
resolver = MyResolver(args.port)
resolver.wait_for_requests()



