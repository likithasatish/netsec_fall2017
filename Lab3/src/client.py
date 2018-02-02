import asyncio
import zlib
import playground
from playground.network.common import StackingProtocol,StackingTransport,StackingProtocolFactory
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32,UINT8,UINT16, STRING, BUFFER, BOOL
from playground.network.packet.fieldtypes.attributes import Optional
from playground.asyncio_lib.testing import TestLoopEx
from playground.network.testing import MockTransportToProtocol
from playground.common.Timer import Timer, Seconds
import random
from .Packet_Type import PEEPPacket


class PeepClientTransport(StackingTransport):

	def __init__(self,protocol,transport):
		super().__init__(transport)
		self.protocol = protocol
		self.transport = transport
		super().__init__(self.transport)

	def write(self, data):
		self.protocol.Chunky(data)

	def close(self):
		self.protocol.shutdown()


class PEEPClientProtocol(StackingProtocol):

	def __init__(self):
		self.transport = None
		self.exc = None
		self.SmartStart = random.randrange(9999)
		self.packets = [] 
		self.SOSequence = 0
		self.session = 0
		self.timers = []
		self.check = 0

# -------------------------------------- Checksum ------------------------------------------------------------
	
	def calculateChecksum(self,pc):#working fine no need to change
		oldChecksum = pc.Checksum
		pc.Checksum = 0
		bytes = pc.__serialize__()
		pc.Checksum = zlib.adler32(bytes) & 0xffff
		return pc.Checksum

	def verifyChecksum(self,pc):#working fine no need to change
		received_Checksum = pc.Checksum
		pc.Checksum = 0
		bytes = pc.__serialize__()
		if received_Checksum == zlib.adler32(bytes) & 0xffff:
			return True
		else:
			return False

# -------------------------------------- Checksum Ends------------------------------------------------------------


# -------------------------------------- Send SYN PACK------------------------------------------------------------
	
	def sendSYN(self):#working fine no need to change
		pack = PEEPPacket()
		pack.Type = 0
		pack.SequenceNumber = self.SmartStart
		self.SmartStart += 1
		pack.Checksum = self.calculateChecksum(pack)
		packet4Bytes = pack.__serialize__()
		self.transport.write(packet4Bytes)
		#print("SYN Packet Sent")

# -------------------------------------- Send ACK PACK------------------------------------------------------------

	def sendACK(self,pc):
		pack = PEEPPacket()
		pack.Type = 2
		pack.SequenceNumber = pc.Acknowledgement
		self.SmartStart += 1
		self.SOSequence = self.SOSequence + pc.SequenceNumber + 1
		pack.Acknowledgement = pc.SequenceNumber + 1
		pack.Checksum = self.calculateChecksum(pack)
		packet4Bytes = pack.__serialize__()
		self.transport.write(packet4Bytes)
		#print("ACK Packet Sent")

# -------------------------------------- Sending DATA Process ------------------------------------------------------------

	def sendingDATA(self, pack):
		packet4Bytes = pack.__serialize__()
		self.transport.write(packet4Bytes)
		#print("ClientData Packet Sent")
		timer = Timer(Seconds(2),self.sendingDATA,pack)
		self.timers.append(timer)
		timer.start()

	def sendDATA(self, pc):
		pack = PEEPPacket()
		pack.Type = 5
		pack.SequenceNumber = self.SmartStart
		pack.Data = pc
		self.SmartStart = self.SmartStart + len(pc) + 1
		pack.Checksum = self.calculateChecksum(pack)
		self.packets.append(pack)
		self.sendingDATA(pack)

	def Chunky(self,data):
		while len(data) > 0:
			chunk = data[:1024]
			data = data[1024:]
			self.sendDATA(chunk)     
		# write code to check whether there is any backlog.

# -------------------------------------- Sending DATA-ACK Process ------------------------------------------------------------

	def sendDataACK(self,pc):
		#print("raching here")
		pack = PEEPPacket()
		pack.Type = 2
		pack.Acknowledgement = pc.SequenceNumber + len(pc.Data)
		self.SOSequence = pack.Acknowledgement + 1
		pack.Checksum = self.calculateChecksum(pack)
		packet4Bytes = pack.__serialize__()
		self.transport.write(packet4Bytes)
		#print("Data - ACK Packet Sent")

# -------------------------------------- Send RIP PACK------------------------------------------------------------

	def sendRIP(self):
		pack = PEEPPacket()
		pack.Type = 3
		pack.SequenceNumber = 0
		pack.Acknowledgement = 0
		pack.Checksum = self.calculateChecksum(pack)
		packet4Bytes = pack.__serialize__()
		self.transport.write(packet4Bytes)
		#print("RIP Packet Sent")
		

	def sendRIPACK(self):
		pack = PEEPPacket()
		pack.Type = 4
		pack.SequenceNumber = 0
		pack.Acknowledgement = 0
		pack.Checksum = self.calculateChecksum(pack)
		packet4Bytes = pack.__serialize__()
		self.transport.write(packet4Bytes)
		#print("RIP Packet Sent")
		rip_timer = Timer(Seconds(2),self.abort_connection)
		rip_timer.start()
	
	def abort_connection(self):
		#print(self.packets)
		#print(self.timers)
		self.transport.close()


# -------------------------------------- Managing Retransmission ------------------------------------------------------------

	def binarySearch(self,pc):
		first = 0
		last = len(self.packets)-1
		found = False
		while first<=last and not found:
			midpoint = (first + last)//2
			if self.packets[midpoint].SequenceNumber + len(self.packets[midpoint].Data)  == pc:
				found = True
				index= midpoint
			else:
				if  pc < self.packets[midpoint].SequenceNumber + len(self.packets[midpoint].Data):
					last = midpoint-1
				else:
					first = midpoint+1
		if found:
			return index
		else:
			index = -1
			return index

	def DataStructure(self, pc):
		index = self.binarySearch(pc.Acknowledgement)
		#print("reached client data structure")
		if index > -1:
			self.packets.pop(index)
		
		
# -------------------------------------- END OF Managing Retransmission ------------------------------------------------------------


	def connection_made(self, transport):
		print("Initialized transport layer handshake with  {}".format(transport.get_extra_info("peername")))
		self.transport = transport
		self.deserializer = PEEPPacket.Deserializer()
		self.sendSYN()
	
	def data_received(self, data):
		self.deserializer.update(data)
		for pkt in self.deserializer.nextPackets():

# -------------------------------------- Handshake ------------------------------------------------------------

			if self.session == 0:  
				if pkt.Type == 1:
					#print("SYN-ACK Packet Received")
					if self.verifyChecksum(pkt):
						#print("SYN-ACK Packet Verified")
						if pkt.Acknowledgement == self.SmartStart:
							self.sendACK(pkt)
							self.session = 1 
							#print("handshake Successful: Initiating Session")
							self.higherProtocol().connection_made(PeepClientTransport(self, self.transport))
						else:
							self.exc = "LOL! Nice Try!"
							self.connection_lost(None)
						
					else:
						self.exc = "Checksum Error during connection: Closing Connection"
						self.connection_lost(None)
				else:
					self.exc = "Packet Type Exception: Nice Try!4"
					self.connection_lost(None)

# ------------------------------------ Handshake Ends - Session Initiated ---------------------------------------
			
			elif self.session == 1:
				if pkt.Type == 2:
					#print("ACK Packet Received")
					if self.verifyChecksum(pkt):
						#print("ACK Packet Verified")
						self.DataStructure(pkt)
						i = 0
						while i < len(self.timers):
							timer = self.timers[i]
							if timer._callbackArgs[0].SequenceNumber < pkt.Acknowledgement:
								timer.cancel()
								self.timers = self.timers[:i] + self.timers[i+1:]
								i -= 1
							i += 1
					else:
						print("Checksum Error with Acknowledgement: Will Have to resend Packet")
						#will wait for timeout to resend packet

# ------------------------------------ Data Receiving ---------------------------------------

				elif pkt.Type == 5:
					#print("clientData Packet Received")
					if self.verifyChecksum(pkt):
						#print("clientData Verified")
						#print(self.SOSequence)
						#print(pkt.SequenceNumber)
						# if this is the expected data packet return an ack
						if pkt.SequenceNumber == self.SOSequence:
							#print("#################### PKT ACCEPTED #######################")
							self.higherProtocol().data_received(pkt.Data)
							self.sendDataACK(pkt)
							#make sure pkt is sent to higher protocol after ack is sent
						else:
							print(" ")
							#print("packet dropped client"+ "#####client")
							#print(pkt.SequenceNumber - self.SOSequence)
					else:
						print("Checksum Error with Data packet: Acknowledgement not Sent")
						# Do Nothing?		

# ------------------------------------ Session Ends - RIP Initiated ---------------------------------------
#			if self.session == 2:  
				elif pkt.Type == 3:
					#print("RIP Packet Received")
					if self.verifyChecksum(pkt):
						#print("RIP Packet Verified")
						self.sendRIPACK()
						
					else:
						self.exc = "Checksum Error during connection: Closing Connection"
						#self.higherProtocol().connection_lost(PeepServerTransport(self, self.transport))
						self.connection_lost(None)
	
				elif pkt.Type == 4:
					print("RIP-ACK Packet Received")
					if self.verifyChecksum(pkt):
						#print("RIP-ACK Packet Verified")
						self.exc = "RIP"
						self.check = 1
						self.transport.close()
					else:
						self.exc = "Checksum Error during connection: Closing Connection"
						self.connection_lost(None)

				else:
					self.exc = "Packet Type Exception: Nice Try!3"
					self.connection_lost(None)

			else:
				exc = " Error with Session: Terminating Connection"
				self.connection_lost(None)

	def shutdown(self):
		if len(self.packets) == 0:
			self.sendRIP()
		else:
			#print(len(self.packets))
			t = Timer(Seconds(2),self.shutdown)
			t.start()

				
	def connection_lost(self, exc):
		self.transport.close()
#		self.transport = None
		asyncio.get_event_loop().stop()

Clientfactory = StackingProtocolFactory(lambda: PEEPClientProtocol())
