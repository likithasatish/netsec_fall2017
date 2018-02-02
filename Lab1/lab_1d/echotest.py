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

class authenticationmessage(PacketType):

    DEFINITION_IDENTIFIER = "lab.server1.authenticationmessage"

    DEFINITION_VERSION = "2.0"

    FIELDS = [

        ("imageID",INT64),

        ("pixelSequence",INT64)

        ]


class validate(PacketType):

    DEFINITION_IDENTIFIER = "lab.server2.validate"

    DEFINITION_VERSION = "4.0"

    FIELDS = [

            ("imageID",INT64),

            ("boo",BOOL)

            ]

packet2 = authenticationmessage()


packet4 = validate()


packet2.imageID = 7

packet2.pixelSequence = 100111111001

packet4.imageID = 7


packet2s = packet2.__serialize__()


class EchoServerProtocol(asyncio.Protocol):

	def __init__(self):
		self.transport= None

	def connection_made(self,transport):
		self.transport = transport
		print ("being called")
		self._deserializer = PacketType.Deserializer()

	def data_received(self,data):
		self._deserializer.update(data)
		for packet in self._deserializer.nextPackets():

			if isinstance(packet,initiateconnection):
				print ("Server : Connection Initiated by Client")
				self.transport.write(packet2s)
	
			elif isinstance(packet,requestvalidation):
				print ("Server : Validation requested")
				print ("Answer") 
				print(packet.answer)
				if (packet.answer == "H"):
					packet4.boo = True
				else:
					packet4.boo = False

				packet4s = packet4.__serialize__()
				self.transport.write(packet4s)
					
	def connection_lost(self,reason = None):
		print ("Lost connection to client. Cleaning up.")
		self.transport = None
   
loop = asyncio.get_event_loop()
coro = playground.getConnector().create_playground_server(lambda: EchoServerProtocol(), 101)
server = loop.run_until_complete(coro)
print("Echo Server Started at {}".format(server.sockets[0].gethostname()))
loop.run_forever()
loop.close()
        

