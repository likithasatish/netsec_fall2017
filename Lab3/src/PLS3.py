from Crypto.PublicKey import RSA
import hashlib

class PLSProtocol(StackingProtocol):
    def __init__(self):
        super().__init__()
	self.session = 0
	self.clientNonce = random.getrandbits(64)
	self.serverNonce = random.getrandbits(64)
	self.PKcr = random.getrandbits(128)
	self.Pks = random.getrandbits(128)
	self.m = hashlib.sha1()

   def data_received(self,data):
	self.deserializer.update(data)
	for pkt in self.deserializer.nextPackets():
            self.handle_packet(pkt)
   
   def handle_packet(self,pkt):
	if isinstance(pkt, PlsHello):
           if self.session == 0
		print ("Recieved Client Hello")
		serverhello = PlsHello()
		serverhello.Nonce = self.serverNonce
		serverhello.Certs = []
		serverhello.Certs.append(#firstcertificate)
		serverhello.Certs.append(#secondcertificate)
		serverhello.Certs.append(#thirfcertificate)
		shandshake1 = serverhello.__serialize__()
		self.transport.write(shandshake1)
		self.m.update(shandshake1)
		self.session = 1
		print("server hello sent : handshake step 1 done")
		
	    elif self.session == 1
		print ("Recieved Server Hello")
		ClientKX = PlsKeyExchange()
		ClientKX.NoncePlusOne = pkt.Nonce + 1
		PKc = #encryptit
		ClientKX.PreKey = PKc
		ckeyexchange = ClientKX.__serialize__()
		self.transport.write(ckeyexchange)
		self.m.update(ckeyexchange)
		self.session = 2
		print ("Client Key Exchange")

	elif isinstance(pkt, PlsKeyExchange):
	    if self.session == 2:
		print ("Recieved Client Key Exchange")
		ServerKX = PlsKeyExchange()
		ServerKX.NoncePlusOne = pkt.Nonce + 1
		PKc = #encryptit
		ServerKX.PreKey = PKc
		skeyexchange = ServerKX.__serialize__()
		self.transport.write(skeyexchange)
		self.m.update(skeyexchange)
		self.session = 3
		print ("Server Key Exchange")

	    elif self.session == 3:
		print ("Recieved Server Key Exchange")
		client_HF = PlsHandshakeDone()
		client_digest = self.m.digest()
		client_HF.ValidationHash = client_digest
		chdf = client_HF.__serialize__()
		self.transport.write(chdf)
		self.session = 4
		print ("Client Handshake Finished")

	elif isinstance(pkt, PlsHandshakeDone):
	    if self.session == 4:
		print ("Recieved Server Key Exchange")
		server_HF = PlsHandshakeDone()
		server_digest = self.m.digest()
		if (server_digest == pkt.ValidationHash):
			server_HF.ValidationHash = server_digest
			shdf = server_HF.__serialize__()
			self.transport.write(shdf)
			self.session = 5
			print ("Server Handshake Finished")

	    if self.session == 5:
		#Data Transmission
		
class PLSServerProtocol(PLSProtocol):
    def connection_made(self, transport):
        print("PLSServer: Received a connection from {}".format(transport.get_extra_info("peername")))
        self.transport = transport


class PLSClientProtocol(PLSProtocol):
    def connection_made(self, transportimport hashlib):
        print("PLSClient: Connection established with server")
        self.transport = transport
	self.initiatehandshake()

    def initiatehandshake(self)
	clienthello = PlsHello()
	clienthello.Nonce = self.clientNonce
	cleinthello.Certs = []
	clienthello.Certs.append(#firstcertificate)
	clienthello.Certs.append(#secondcertificate)
	clienthello.Certs.append(#thirfcertificate)
	chandshake1 = clienthello.__serialize__()
	self.transport.write(chandshake1)
	self.m.update(chandshake1)
	print("client hello sent : handshake initiated")

