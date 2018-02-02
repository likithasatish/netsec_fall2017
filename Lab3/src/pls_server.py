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




class PLSServerTransport(StackingTransport):

	def __init__(self,protocol,transport):
		self.protocol = protocol
		self.transport = transport
		super().__init__(self.transport)

	def write(self, data):
		self.protocol.write(data)

	def close(self):
		self.protocol.close()


class PLSServerProtocol(StackingProtocol):
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
		#print("*******************Initialisation complete(SERVER)********************")

# ---------------------------------------------- PLS Hello -------------------------------------  #     

	def sendPlsHello(self):
		#print("*********** LET US SEND HELLO FROM SERVER **********")
		serverhello = PlsHello()
		serverhello.Nonce = self.HelloNonce
		self.servernonce = serverhello.Nonce.to_bytes(8, byteorder='big')
		serverhello.Certs = getCertsForAddr(self.address)
		shandshake1 = serverhello.__serialize__()
		self.m.update(shandshake1)
		self.transport.write(shandshake1)
		#print("******** SERVER SENDS HELLO : HANDSHAKE INITIATED *******")

	def HandleHello(self, pc):
		#print("******************* TIME TO HANDLE HELLO ON SERVER ********************")
		self.clientnonce = pc.Nonce.to_bytes(8, byteorder='big')
		if (self.validate(pc.Certs)):
			#print("**************** GOING TO SEND HELLO NOW ***************")
			self.sendPlsHello()
			self.NCc = pc.Nonce
			self.Received_Certificates = pc.Certs
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
		#print("************ TIME FOR SERVER TO SEND KEY EXCHANGE PACKET ********************")
		ServerKX = PlsKeyExchange()
		ServerKX.NoncePlusOne = self.NCc + 1
		#print("1")
		self.PKs = (CipherUtil.getCertFromBytes(self.Received_Certificates[0])).public_key()
		#print("1")
		ServerKX.PreKey = self.PKs.encrypt(os.urandom(16),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
		self.serverprekey = ServerKX.PreKey
		#print("1")		
		skeyexchange = ServerKX.__serialize__()
		self.m.update(skeyexchange)
		self.transport.write(skeyexchange)
		#print ("Server Key Exchange Sent")

	def HandlePlsKeyExchange(self,pc):
		# --------------- Why are we not doing anything with received packet here?? ----- #
		self.clientprekey = pc.PreKey
		self.sendPlsKeyExchange(pc)

# ---------------------------------------------- PLS Handshake Done -------------------------------------  #    

	def sendPlsHandshakeDone(self):
		client_HF = PlsHandshakeDone()
		client_digest = self.m.digest()
		client_HF.ValidationHash = client_digest
		chdf = client_HF.__serialize__()
		self.transport.write(chdf)
		#print ("Server Handshake Finished")

	def HandlePlsHandshakeDone(self,pc):
		self.sendPlsHandshakeDone()
		#print("************** BACK TO HANDLE PLS HANDSHAKE DONE ********************")
		self.generate_keys()
		#print("************** BACK TO HANDLE PLS HANDSHAKE DONE - 2 ********************")
		self.higherProtocol().connection_made(PLSServerTransport(self, self.transport))

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
		h = hmac.HMAC(self.MKc, hashes.SHA1(), backend=default_backend())
		checking = h.update(ct)
		#print(checking)
		try:
			h.verify(mac)
			return True
		except Exception as e:
			#print(e)
			return False

	def Decrypt_Engine(self, data):
		return self.aesDecrypterClient.update(data)
		
	def Encrypt_Engine(self, data):
		return self.aesEncrypterServer.update(data)
		
	def MAC_Engine(self, ciphertext):
		hmac_engine = CipherUtil.MAC_HMAC_SHA1(self.MKs)
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

		# creating encrypter and decrypter
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
		ciphertext = self.Encrypt_Engine(data)
		mac = self.MAC_Engine(ciphertext)
		pls_data = PlsData()
		pls_data.Ciphertext = ciphertext
		pls_data.Mac = mac
		#print(pls_data.Ciphertext)
		#print(pls_data.Mac)
		serial_data = pls_data.__serialize__()
		self.transport.write(serial_data)


	def connection_made(self,transport):
		#print("********************* Server connection_made called ****************************")
		print("Initialized handshake with  {}".format(transport.get_extra_info("peername")))
		self.transport = transport
		self.address, self.port = transport.get_extra_info("sockname")
		self.Self_Certificate = getPrivateKeyForAddr(self.address)
		self.Inter_Certificate = getCertsForAddr(self.address)
		self.Root_Certificate = getRootCert()
		self.deserializer = BasePacketType.Deserializer()


	def data_received(self, data):
		#print("********************* DATA RECEIVED CALLED AT SERVER **********************")
		self.deserializer.update(data)
		for pkt in self.deserializer.nextPackets():
			if type(pkt) is PlsHello:
				#print("********************* HELLO PACKET RECEIVED BY SERVER **********************")
				self.m.update(pkt.__serialize__())
				self.HandleHello(pkt)
			elif type(pkt) is PlsKeyExchange:
				#print("********************* PLS EXCHANGE PACKET RECEIVED CALLED AT SERVER **********************")
				self.m.update(pkt.__serialize__())
				self.HandlePlsKeyExchange(pkt)
			elif type(pkt) is PlsHandshakeDone:
				#print("********************* HANDSHAKEDONE PACKET RECEIVED CALLED AT SERVER **********************")
				self.HandlePlsHandshakeDone(pkt)
			elif type(pkt) is PlsData:
				#print("********************* PLS DATA PACKET RECEIVED CALLED AT SERVER **********************")
				#print(pkt.Ciphertext)
				#print(pkt.Mac)
				self.HandlePlsData(pkt)
			elif type(pkt) is PlsClose:
				self.transport.close()
			else:
				print("Error")

	def connection_lost(self):
		self.transport.close()
		self.transport = None
