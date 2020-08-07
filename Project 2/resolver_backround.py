#Abraham Gale 2020
# You should not change this file at all.
import threading
import socket
import struct
import argparse
import concurrent.futures
import select
from sys import argv
UDP_LIMIT = 10
TCP_ONE_CONNECTION = 3
TCP_THREADS = 10
TCP_TIMEOUT = 15
class DnsResolver:
	def __init__(self, port):
		self.port = port
		#define variables and locks you will need here
	def wait_for_requests(self):
		tcp = threading.Thread(target=self.get_tcp_connections)
		tcp.start()

		udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		udp_sock.bind(('', self.port))
		udp_sock.setblocking(0)
		answers = []
		with concurrent.futures.ThreadPoolExecutor(max_workers=UDP_LIMIT) as executor:
			while True:
				read, _, _ = select.select([udp_sock], [], [], 0)
				if read:
					data, addr = udp_sock.recvfrom(512)
					answers.append(executor.submit(self.process_udp, data, addr))
				for i, answer in enumerate(answers):
					if answer.done():
						udp_sock.sendto(answer.result()[0], answer.result()[1])
						answers[i] = None
				answers = [answer for answer in answers if answer != None]
	def get_dns_response(self, query):
		threading.sleep(2)
		return b'Placeholder'
	def process_tcp(self, sock):
		sock.settimeout(TCP_TIMEOUT)
		done = False
		while not done:
			try:
				with concurrent.futures.ThreadPoolExecutor(max_workers=TCP_ONE_CONNECTION) as executor:
					length = sock.recv(2)
					if not length:
						break
					query = sock.recv(struct.unpack('!H', length)[0])
					if not length:
						break
					answers = []
					answers.append(executor.submit(self.get_dns_response, query))
			except RuntimeError as exc:
				print(exc)
				done = True
			for i, answer in enumerate(answers):
				if answer != None and answer.done():
					res = answer.result()
					sock.send(struct.pack('!H',len(res)) + res)
					answers[i] = None
		while answers:
			for i, answer in enumerate(answers):
				if answer != None and answer.done():
					res = answer.result()
					sock.send(struct.pack('!H',len(res)) + res)
					answers[i] = None
			answers = [answer for answer in answers if answer != None]
		sock.close()
	def process_udp(self, query, address):
		return self.get_dns_response(query), address
	def get_tcp_connections(self):
		server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		server_sock.bind(('', self.port))
		server_sock.listen(TCP_THREADS)
		while True:
			sock, addr = server_sock.accept()
			tcp_thread = threading.Thread(target=self.process_tcp, args=(sock,))
			tcp_thread.start()
