import struct
import time
from random import randint
import copy
import binascii
NAME_RR_SET = {5, 12, 2, 7, 3, 4, 8, 9, 15}
MX = 15
TWO_NAME_RR_SET = {6, 14}
def unpack_options(options):
	answer_dict = {}
	answer_dict['RCODE'] = options & 0xF
	options >>= 4
	answer_dict['ZERO'] = options & 0x7
	options >>= 3
	answer_dict['RA'] = options & 0x1
	options >>= 1
	answer_dict['RD'] = options & 0x1
	options >>= 1
	answer_dict['TC'] = options & 0x1
	options >>= 1
	answer_dict['AA'] = options & 0x1
	options >>= 1
	answer_dict['OPCODE'] = options & 0xF
	options >>= 4
	answer_dict['QR'] = options & 0x1
	options >>= 1
	return answer_dict
def pack_options(rcode, RA, RD, TC, AA, OPCODE, QR, ZERO):
	answer = 0x0000
	#~ items = struct.pack()
	answer |= rcode & 0xf
	answer |= (RA  & 0x1) << 7
	answer |= (RD  & 0x1) << 8
	answer |= (TC  & 0x1) << 9
	answer |= (AA  & 0x1) << 10
	answer |= (OPCODE  & 0xf) << 11
	answer |= (QR  & 0x1) << 15
	answer |= (ZERO & 0x7) << 4
	return answer
class DNSQuery:
	def __init__(self, query=None):
		if query != None:
			self.header = self.parse_header(query)
			if self.header['QDCOUNT']:
				self.question, index = self.parse_question(query, 12)
			else:
				self.question = {}
				index = 12
			self.answers = []
			self.rdata_indexes = []
			self.query_text = query
			while index < len(query):
				answer, data_index, index = self.parse_RR(query, index)
				self.answers.append(answer)
				self.rdata_indexes.append(data_index)
			if self.to_bytes() != self.query_text:
				print(self.to_bytes(), self.query_text)
				print('PARSE ERROR PLEASE EMAIL PROFESSOR')
		else:
			self.header = self.parse_header(DNSQuery.make_header())
			self.question = {}
			self.answers = []
			self.query_text = b''
	def to_bytes(self):
		query = bytearray(self.dict_to_header(self.header))
		if self.question:
			query += self.name_to_bytes(query, 12, self.question['NAME'])
			query += struct.pack('!HH', self.question['QTYPE'], self.question['QCLASS'])
		for record in self.answers:
			query += self.make_RR(query, record)
		return query
	@staticmethod
	def dict_to_header(dictionary):
		return DNSQuery.make_header(dictionary['ID'], dictionary['QDCOUNT'], dictionary['ANCOUNT'],dictionary['NSCOUNT'],dictionary['ARCOUNT'],
			dictionary['RCODE'],dictionary['RA'],dictionary['RD'],dictionary['TC'],dictionary['AA'],dictionary['OPCODE'],dictionary['QR'], dictionary['ZERO'])
	@staticmethod
	def make_header(qid=0, q_number = 0, a_number = 0, auth_num = 0, add_r = 0, rcode = 0, RA = 0, RD = 0, TC = 0, AA=0, OPCODE=0, QR=0, ZERO=0):
		dns_header_string = '!HHHHHH'
		dns_options = pack_options(rcode, RA, RD, TC, AA, OPCODE, QR, ZERO)
		dns_header_struct = struct.Struct(dns_header_string)
		header = dns_header_struct.pack(qid, dns_options, q_number, a_number, auth_num, add_r)
		return header
	@staticmethod
	def parse_header(query_text):
		dns_header_string = '!HHHHHH'
		dns_header_struct = struct.Struct(dns_header_string)
		header_items = dns_header_struct.unpack(query_text[:12])
		answer_dict = {'ID':header_items[0], 'QDCOUNT':header_items[2],'ANCOUNT':header_items[3], 'NSCOUNT':header_items[4], 'ARCOUNT':header_items[5]}
		#header = dns_header_struct.pack(qid, dns_options, q_number, a_number, auth_num, add_r)
		answer_dict.update(unpack_options(header_items[1]))
		return answer_dict
	@staticmethod
	def compress_name(query_text, index, byte_name, byte_name_locations):
		name_so_far = bytearray()
		best = -1
		for i, loc in enumerate(byte_name_locations):
			found_in_query = query_text.find(byte_name[loc:], 0, index)
			if found_in_query != -1:
				num = bytearray(struct.pack('!H', found_in_query))
				flag = 0xc0
				num[0] |= flag
				byte_name_locations = byte_name_locations[:i]
				return DNSQuery.compress_name(query_text, index, byte_name[:loc] + num, byte_name_locations)
		return byte_name
	@staticmethod
	def name_to_bytes(query_text, index, name):
		byte_name_locations = []
		name = bytearray(name)
		if name == b'.':
			return b'\0'
		byte_name = bytearray()
		label = b''
		while name:
			next_dot = name.find(b'.')
			if next_dot == -1:
				next_dot = len(name)
			label = name[:next_dot]
			byte_name_locations.append(len(byte_name))
			byte_name += struct.pack('!B', len(label))
			byte_name += label
			name = name[next_dot + 1:]
		if byte_name[-1] != b'\0':
			byte_name += b'\0'
		return DNSQuery.compress_name(query_text, index, byte_name, byte_name_locations)
	@staticmethod
	def bytes_to_name(query_text, start_index):
		name = bytearray()
		current = start_index
		while query_text[current] != 0:
			if query_text[current] >> 6 == 3:
				index = struct.unpack('!H', query_text[current:current + 2])[0] & ~0xc000
				return name + DNSQuery.bytes_to_name(query_text, index)[0], current + 2
			else:
				length = query_text[current]
				name += query_text[current + 1:current + length + 1]
				name += b'.'
				current += length + 1
		if not name:
			name += b'.'
		return name, current + 1
	@staticmethod
	def parse_question(query_text, index):
		name, index = DNSQuery.bytes_to_name(query_text, index)
		answer_dict = {}
		answer_dict['NAME'] = name
		type_class = struct.unpack('!HH', query_text[index:index + 4])
		index = index + 4
		answer_dict['QTYPE'] = type_class[0]
		answer_dict['QCLASS'] = type_class[1]
		return answer_dict, index
	@staticmethod
	def parse_RR(record, start):
		name, index = DNSQuery.bytes_to_name(record, start)
		answer_dict = {}
		answer_dict['NAME'] = name
		answer_dict['TYPE'], answer_dict['CLASS'], answer_dict['TTL'],answer_dict['RDLENGTH'] = struct.unpack('!HHIH', record[index:index + 10])
		index += 10
		data_index = index
		temp_index = index
		answer_dict['RDATA'] = []
		rdlength = answer_dict['RDLENGTH']
		if answer_dict['TYPE'] == MX:
			answer_dict['RDATA'].append(record[temp_index: temp_index + 2])
			temp_index += 2
			rdlength -= 2
		if answer_dict['TYPE'] in NAME_RR_SET:
			rdata, index2 = DNSQuery.bytes_to_name(record, temp_index)
			answer_dict['RDATA'].append(rdata)
			rdlength -= (index2 - temp_index)
			temp_index = index2
		elif answer_dict['TYPE'] in TWO_NAME_RR_SET:
			rdata, index2 = DNSQuery.bytes_to_name(record, temp_index)
			answer_dict['RDATA'].append(rdata)
			rdlength -= index2 - temp_index
			temp_index = index2
			rdata, index2 = DNSQuery.bytes_to_name(record, temp_index)
			answer_dict['RDATA'].append(rdata)
			rdlength -= index2 - temp_index
			temp_index = index2
		answer_dict['RDATA'].append(record[temp_index:temp_index + rdlength])
		# answer_dict['RDINDEX'] = index
		index += answer_dict['RDLENGTH']
		return answer_dict, data_index, index
	@staticmethod
	def remove_name(name_string):
		zero = name_string.index(b'\0') + 1
		return name_string[zero:]
	@staticmethod
	def make_RR(query_so_far, record_dict):
		record = DNSQuery.name_to_bytes(query_so_far, len(query_so_far), record_dict['NAME'])
		record += struct.pack('!HHI', record_dict['TYPE'], record_dict['CLASS'], record_dict['TTL'])
		rdata = bytearray()
		data_to_parse = record_dict['RDATA']
		if record_dict['TYPE'] == MX:
			rdata += record_dict['RDATA'][0]
			data_to_parse = data_to_parse[1:]
		if record_dict['TYPE'] in NAME_RR_SET:
			temp_data = DNSQuery.name_to_bytes(query_so_far + record  + b'00' + rdata, len(query_so_far + record+ b'00'  + rdata), data_to_parse[0])
			rdata += temp_data
			data_to_parse = data_to_parse[1:]
		elif record_dict['TYPE'] in TWO_NAME_RR_SET:
			temp_data = bytearray()
			for name in data_to_parse[:2]:
				temp_data = DNSQuery.name_to_bytes(query_so_far + record + b'00' + rdata, len(query_so_far + record+ b'00'  + rdata), name)
				rdata += temp_data
			data_to_parse = data_to_parse[2:]
		rdata += data_to_parse[0]
		record += struct.pack('!H', len(rdata))
		record += rdata
		return record
	def __repr__(self):
		return str(self.header) + str(self.question) + str(self.answers)
