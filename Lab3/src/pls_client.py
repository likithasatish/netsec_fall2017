import playground
import cryptography
import logging, os
import hashlib, struct
import random
from .PLSPacket import *
from playground.network.common import StackingProtocol,StackingTransport,StackingProtocolFactory
from playground.common import CipherUtil
from .CertFactory import getPrivateKeyForAddr, getCertsForAddr, getRootCert
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers import Cipher , algorithms, modes
backend = default_backend()

class PLSClientTransport(StackingTransport):

	def __init__(self,protocol,transport):
		self.protocol = protocol
		self.transport = transport
		super().__init__(self.transport)

	def write(self, data):
		self.protocol.write(data)

	def close(self):
		self.protocol.close()


class PLSClientProtocol(StackingProtocol):
	def __init__(self):
		self.HelloNonce = int.from_bytes(os.urandom(8), byteorder='big')
		self.m = hashlib.sha1()
		self.Received_Certificates = []
		self.PKs = 0
		self.MKs = 0
		self.PreKey = os.urandom(16)
		self.digest = b''
		self.seed = b'PLS1.0'
		self.NCs = random.getrandbits(64)
		self.NCc = 0
		self.serverprekey = 0
		self.clientprekey = 0
		self.clientnonce = 0
		self.servernonce = 0
		self.PKc = int.from_bytes(os.urandom(16), byteorder='big')
		self.SKc = int.from_bytes(os.urandom(16), byteorder='big')
		self.EKs = b''
		self.EKc = b''
		self.IVs = b''
		self.IVc = b''
		self.MKs = b''
		self.MKc = b''
		self.block_size = 128
		#print("*******************Initialisation complete(CLIENT)********************")

# ---------------------------------------------- PLS Hello -------------------------------------  #		

	def sendPlsHello(self):
		clienthello = PlsHello()
		clienthello.Nonce = self.HelloNonce
		self.clientnonce = clienthello.Nonce.to_bytes(8, byteorder='big')
		clienthello.Certs = getCertsForAddr(self.address)
		chandshake1 = clienthello.__serialize__()
		self.m.update(chandshake1)
		self.transport.write(chandshake1)
		#print("********** CLIENT SENDS HELLO INITIATES HANDSHAKE **********")

	def HandleHello(self, pc):
		#print("******************* TIME TO HANDLE HELLO ON CLIENt ********************")
		self.Nc = pc.Nonce
		self.servernonce = pc.Nonce.to_bytes(8, byteorder='big')
		if (self.validate(pc.Certs)):
			#print("**************** GOING TO SEND PLsKeyExchange NOW ***************")
			self.sendPlsKeyExchange(pc)
		else:
			print("*********** CERTIFICATE CHAIN NOT VALID ****************")

	def validate(self, certificate):
		#print("********* START VALIDATION ***********")
		for i in range(1, len(certificate)):
			cert = x509.load_pem_x509_certificate(certificate[i - 1], default_backend())
			pk = x509.load_pem_x509_certificate(certificate[i], default_backend()).public_key()
			try:
				pk.verify(
				cert.signature,
				cert.tbs_certificate_bytes,
				padding.PKCS1v15(),
				hashes.SHA256()
				)
				#print("VALIDATION COMPLETE")
				return True
			except Exception as exc:
				#print(e)
				print("VALIDATION FAILED")

# ---------------------------------------------- PLS Key Exchange -------------------------------------  #	

	def sendPlsKeyExchange(self,pc):
		#print("************ TIME FOR CLIENT TO SEND KEY EXCHANGE PACKET ********************")
		ClientKX = PlsKeyExchange()
		ClientKX.NoncePlusOne = pc.Nonce + 1
		self.PKs = (CipherUtil.getCertFromBytes(pc.Certs[0])).public_key()
		ClientKX.PreKey = self.PKs.encrypt(os.urandom(16),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
		self.clientprekey = ClientKX.PreKey		
		ckeyexchange = ClientKX.__serialize__()
		self.m.update(ckeyexchange)
		self.transport.write(ckeyexchange)
		#print ("Client Key Exchange Sent")

	def HandlePlsKeyExchange(self,pc):
		#print ("Recieved Server Key Exchange")
		# --------------- Why are we not doing anything with received packet here?? ----- #
		self.sendPlsHandshakeDone()

# ---------------------------------------------- PLS Handshake Done -------------------------------------  #	

	def sendPlsHandshakeDone(self):
		#print("***************** TIME to SEND HANDSHAKE FINISHED ****************")
		client_HF = PlsHandshakeDone()
		client_digest = self.m.digest()
		client_HF.ValidationHash = client_digest
		chdf = client_HF.__serialize__()
		self.transport.write(chdf)
		#print ("Client Handshake Finished")

	def HandlePlsHandshakeDone(self,pc):
		#print("Server HandshakeDone Packet Received")
		self.generate_keys()
		#print("************** BACK TO HANDLE PLS HANDSHAKE DONE  ********************")
		self.higherProtocol().connection_made(PLSClientTransport(self, self.transport))
		#print("************** BACK TO HANDLE PLS HANDSHAKE DONE - 2 ********************")

# ---------------------------------------------- PLS Data -------------------------------------  #	
	
	def HandlePlsData(self,pc):
		#print("***************** HANDLE DATA CALLED **********************")
		if self.Verification_Engine(pc.Ciphertext, pc.Mac):
			#print("***************** Verification Engine Works **********************")
			PlainText = self.Decrypt_Engine(pc.Ciphertext)
			#print(PlainText)
			self.higherProtocol().data_received(PlainText)
		else:
			print("Verification Failed")
		
	def Verification_Engine(self, ct, mac):
		#print("***************** Verification Engine Called **********************")
		#print(ct)
		#print(mac)
		h = hmac.HMAC(self.MKs, hashes.SHA1(), backend=default_backend())
		checking = h.update(ct)
		#print(checking)
		try:
			h.verify(mac)
			return True
		except Exception as e:
			print(e)
			return False

	def Decrypt_Engine(self, data):
		return self.aesDecrypterServer.update(data)

	def Encrypt_Engine(self, data):
		return self.aesEncrypterClient.update(data)

	def MAC_Engine(self, ciphertext):
		hmac_engine = CipherUtil.MAC_HMAC_SHA1(self.MKc)
		return hmac_engine.mac(ciphertext)


# ---------------------------------------------- Generate Keys -------------------------------------  #

	def hashinsha(self, data):
		hasher = hashlib.sha1()
		hasher.update(data)
		return hasher.digest()

	def generate_keys(self):
		#print("*************** STARTED GENERATION PROCESS ***************")
		seed = b'PLS1.0' + self.clientnonce +self.servernonce + self.clientprekey + self.serverprekey
		block_0 = self.hashinsha(seed)
		block_1 = self.hashinsha(block_0)
		block_2 = self.hashinsha(block_1)
		block_3 = self.hashinsha(block_2)
		block_4 = self.hashinsha(block_3)
		blocks = block_0 + block_1 + block_2 + block_3 + block_4

		self.EKc = block_0[:16]
		self.EKs = block_0[16:] + block_1[:12]
		self.IVc = block_1[12:] + block_2[:8]
		self.IVs = block_2[8:] + block_3[:4]
		self.MKc = block_3[4:]
		self.MKs = block_4[:16]
		
		self.aesEncrypterServer = Cipher(algorithms.AES(self.EKs), modes.CTR(self.IVs), backend = default_backend()).encryptor()
		self.aesEncrypterClient = Cipher(algorithms.AES(self.EKc), modes.CTR(self.IVc), backend = default_backend()).encryptor()
		self.aesDecrypterClient = Cipher(algorithms.AES(self.EKc), modes.CTR(self.IVc), backend = default_backend()).decryptor()
		self.aesDecrypterServer = Cipher(algorithms.AES(self.EKs), modes.CTR(self.IVs), backend = default_backend()).decryptor()
		#print("------------------ EKc ---------", self.EKc)
		#print("------------------ EKs ---------", self.EKs)
		#print("------------------ IVc ---------", self.IVc)
		#print("------------------ IVs ---------", self.IVs)
		#print("------------------ MKc ---------", self.MKc)
		#print("------------------ MKs ---------", self.MKs)


		
# ---------------------------------------------- PLS CLose -------------------------------------  #	
	
	def close(self,pc):
		shutdown = PlsClose()
		close = shutdown.__serialize__()
		self.transport.write(close)

	def write(self, data):
		#print("*****data received to write****")
		ciphertext = self.Encrypt_Engine(data)
		#print("*****1****")
		mac = self.MAC_Engine(ciphertext)
		#print("*****2****")
		pls_data = PlsData()
		pls_data.Ciphertext = ciphertext
		pls_data.Mac = mac
		#print(pls_data.Ciphertext)
		#print(pls_data.Mac)
		serial_data = pls_data.__serialize__()
		self.transport.write(serial_data)

	def connection_made(self,transport):
		print("Client connection_made called")
		print("Initialized handshake with  {}".format(transport.get_extra_info("peername")))
		self.transport = transport
		self.address, self.port = transport.get_extra_info("sockname")
		self.Self_Certificate = getPrivateKeyForAddr(self.address)
		self.Inter_Certificate = getCertsForAddr(self.address)
		self.Root_Certificate = getRootCert()
		self.deserializer = BasePacketType.Deserializer()
		#print("leaving connection_made")
		self.sendPlsHello()


	def data_received(self, data):
		#print("********************* DATA RECEIVED CALLED AT CLIENT **********************")
		self.deserializer.update(data)
		for pkt in self.deserializer.nextPackets():
			if type(pkt) is PlsHello:
				#print("********************* HELLO PACKET RECEIVED CALLED AT CLIENT **********************")
				self.m.update(pkt.__serialize__())
				self.NCs=pkt.Nonce
				self.HandleHello(pkt)
			elif type(pkt) is PlsKeyExchange:
				#print("********************* PLSEXCHANGE PACKET RECEIVED CALLED AT CLIENT **********************")
				self.m.update(pkt.__serialize__())
				self.serverprekey=pkt.PreKey
				self.HandlePlsKeyExchange(pkt)
			elif type(pkt) is PlsHandshakeDone:
				#print("********************* HANDSHAKE DONE RECEIVED FROM SERVER BY CLIENT **********************")
				self.HandlePlsHandshakeDone(pkt)
			elif type(pkt) is PlsData:
				#print("********************* PLS DATA PACKET RECEIVED CALLED AT CLIENT **********************")
				self.HandlePlsData(pkt)
			elif type(pkt) is PlsClose:
				self.transport.close()
			else:
				print("Error")

	def connection_lost(self):
		self.transport.close()
		self.transport = None



