'''
Created on Feb 15, 2014

@author: sethjn

This sample shows how to do some basic things with playground.
It does not use the PlaygroundNode interface. To see an example
of that, check out computePi.py.
'''

# We will use "BOOL1" and "STRING" in our message definition
from playground.network.packet.fieldtypes import BOOL, STRING, INT64
from playground.network.common import PlaygroundAddress

# MessageDefinition is the base class of all automatically serializable messages
from playground.network.packet import PacketType
import playground

import sys, time, os, logging, asyncio
#logger = logging.getLogger(__name__)

class initiateconnection(PacketType):

    DEFINITION_IDENTIFIER = "lab.client1.initiateconection"

    DEFINITION_VERSION = "1.0"

class requestvalidation(PacketType):

    DEFINITION_IDENTIFIER = "lab.client2.requestvalidation"

    DEFINITION_VERSION = "3.0"

    FIELDS = [

            ("imageID",INT64),

            ("answer",STRING)

            ]


packet3 = requestvalidation()

packet3.imageID = 7

packet3.answer = "H"


packet3s = packet3.__serialize__()

#def firstpacket():
packet1 = initiateconnection()
packet1s = packet1.__serialize__()
#return packet1s	
	

class EchoClientProtocol(asyncio.Protocol):

	def __init__(self):
		self.transport= None

	def connection_made(self,transport):
		self.transport = transport
		self._deserializer = PacketType.Deserializer()
		print ("being called")
		self.transport.write(packet1s)

	def data_received(self,data):
		self._deserializer.update(data)
		for packet in self._deserializer.nextPackets():

			if isinstance(packet,authenticationmessage):
				print("Client : Recaptcha Image Received from Server")
				print("Image Pixel Sequence : ") 
				print(packet.pixelSequence)
				self.transport.write(packet3s)
				
			elif isinstance(packet,validate):
				print("Client : Answer validated by Server")
				print("Validate")
				print(packet.boo)
			
	def connection_lost(self,exc):
		self.transport= None               




loop = asyncio.get_event_loop()
remoteAddress = "20174.1.1.1"
control = EchoClientProtocol()
coro = playground.getConnector().create_playground_connection(lambda:EchoClientProtocol(), remoteAddress, 101)
transport, protocol = loop.run_until_complete(coro)
print("Echo Client Connected. Starting UI t:{}. p:{}".format(transport, protocol))
        #loop.add_reader(sys.stdin, control.stdinAlert)
        #control.connect(protocol)
loop.run_forever()
loop.close()
        
