#python3

import socket
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = True
		# --------- CONSTANTS ------------
		self.version_major = 1
		self.version_minor = 0
		self.msg_hdr_ver = b'\x01\x00'
		self.msg_hdr_rsv = b'\x00\x00'
		self.size_msg_hdr = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
		self.size_msg_hdr_sqn = 2
		self.size_msg_hdr_rnd = 6
		self.size_msg_hdr_rsv = 2
		self.size_msg_mac = 12
		self.size_msg_etk = 256
		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = (self.type_login_req, self.type_login_res, 
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
		# --------- STATE ------------
		self.peer_socket = peer_socket
		self.msg_rec_sqn = 0
		self.msg_snd_sqn = 0
		self.session_key = None
		self.PrivateKey = None
		self.PublicKey = None
		self.tk = None

	def set_key(self, key):
		self.session_key = key

	def set_keypair(self, public, private):
		self.PrivateKey = private
		self.PublicKey = public

	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
		parsed_msg_hdr['sqn'], i = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
		parsed_msg_hdr['rnd'] = msg_hdr[i:i+self.size_msg_hdr_rnd]
		return parsed_msg_hdr
	
	def encrypt_tk(self, tk):
		key = self.PublicKey
		cipher = PKCS1_OAEP.new(key)
		etk = cipher.encrypt(tk)
		return etk
	
	def decrypt_tk(self, etk):
		key = self.PrivateKey
		cipher = PKCS1_OAEP.new(key)
		self.tk = cipher.decrypt(etk)

	def encrypt_payload(self, plain_payload,  header, key, nonce):
		cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_msg_mac)
		cipher.update(header)
		encrypted_payload, tag = cipher.encrypt_and_digest(plain_payload)
		return encrypted_payload, tag
	
	def decrypt_payload(self, encrypted_payload, header, key, nonce, mac):
		cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_msg_mac)
		cipher.update(header)
		try: 
			plain_payload = cipher.decrypt_and_verify(encrypted_payload, received_mac_tag=mac, output=None)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Invalid MAC: ' + e.err_msg) 
		return plain_payload

	# receives n bytes from the peer socket
	def receive_bytes(self, n):

		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received
	

	# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self):

		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')
		
		if int.from_bytes(parsed_msg_hdr['sqn']) <= int(self.msg_rec_sqn):
			raise SiFT_MTP_Error('Message too old! SQN: ' + str(self.msg_rec_sqn) + ' expected, but recieved ' + str(parsed_msg_hdr['sqn']))

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		msg_type = parsed_msg_hdr['typ']

		if msg_type == self.type_login_req:
			try:
				msg_body = self.receive_bytes(msg_len - self.size_msg_hdr - self.size_msg_mac - self.size_msg_etk)
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to receive login message body --> ' + e.err_msg)
			if len(msg_body) != msg_len - self.size_msg_hdr - self.size_msg_mac - self.size_msg_etk: 
				raise SiFT_MTP_Error('Incomplete message body received')
		else: 
			try:
				msg_body = self.receive_bytes(msg_len - self.size_msg_hdr - self.size_msg_mac)
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)
			if len(msg_body) != msg_len - self.size_msg_hdr - self.size_msg_mac: 
				raise SiFT_MTP_Error('Incomplete message body received')
		
		try:
			mac = self.receive_bytes(self.size_msg_mac)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive mac --> ' + e.err_msg)
		
		if msg_type == self.type_login_req:
			try:
				etk = self.receive_bytes(self.size_msg_etk)
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to receive etk --> ' + e.err_msg)
			#etk = msg_body[-256:]
			self.decrypt_tk(etk)
			key = self.tk
		elif msg_type == self.type_login_res:
			key = self.tk
		else:
			key = self.session_key

		nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
		decrypted_payload = self.decrypt_payload(msg_body, msg_hdr, key, nonce, mac)

		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(decrypted_payload)) + '): ')
			print(msg_body.hex())
			print('MAC (' + str(len(mac)) + '):' + mac.hex())
			if parsed_msg_hdr['typ'] == self.type_login_req:
				print('ETK (' + str(len(etk)) + '):' + etk.hex())
			print('------------------------------------------')
		# DEBUG 

		self.msg_rec_sqn = int.from_bytes(parsed_msg_hdr['sqn'])

		return parsed_msg_hdr['typ'], decrypted_payload


	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')

	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):
	
		self.msg_snd_sqn += 1
		sqn = self.msg_snd_sqn.to_bytes(self.size_msg_hdr_sqn, byteorder='big')
		msg_rnd = get_random_bytes(self.size_msg_hdr_rnd)
		msg_len = self.size_msg_hdr + len(msg_payload) + self.size_msg_mac
		msg_etk = b''

		#if the message sent is a login message, account for etk
		if msg_type == self.type_login_req: 
			tk = get_random_bytes(32)
			self.tk = tk
			msg_etk = self.encrypt_tk(tk)	
			msg_len += self.size_msg_etk	
			key = self.tk	
		elif msg_type == self.type_login_res:
			key = self.tk
		else:
			key = self.session_key

		# build message
		msg_hdr_len = msg_len.to_bytes(self.size_msg_hdr_len, byteorder='big')
		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + sqn + msg_rnd + self.msg_hdr_rsv

		nonce = sqn + msg_rnd
		encrypted_payload, msg_mac = self.encrypt_payload(msg_payload, msg_hdr, key, nonce)

		# DEBUG 
		if self.DEBUG:
			print('MTP message to send (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_payload)) + '): ')
			print(msg_payload.hex())
			print('MAC (' + str(len(msg_mac)) + '):' + msg_mac.hex())
			if msg_type == self.type_login_req:
				print('ETK (' + str(len(msg_etk)) + '):' + msg_etk.hex())
			print('------------------------------------------')
		# DEBUG 

		# try to send
		try:
			self.send_bytes(msg_hdr + encrypted_payload + msg_mac + msg_etk)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)
		
		self.msg_snd_sqn = int.from_bytes(sqn)
