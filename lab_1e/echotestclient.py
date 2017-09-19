import sys, time, os, logging, asyncio
import playground
from playground.network.packet.fieldtypes import BOOL, STRING, INT64
from playground.network.common import PlaygroundAddress
from playground.network.packet import PacketType
from playground.network.common import StackingProtocol,StackingTransport,StackingProtocolFactory


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

packet3 = requestvalidation()

packet3.imageID = 7

packet3.answer = "H"

packet3s = packet3.__serialize__()

packet1 = initiateconnection()

packet1s = packet1.__serialize__()


class EchoClientProtocol(asyncio.Protocol):

	def __init__(self):
		self.transport= None

	def connection_made(self,transport):
		self.transport = transport
		self._deserializer = PacketType.Deserializer()
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


class EchoControl:
	def buildProtocol(self):
		return EchoClientProtocol()


class passthrough1(StackingProtocol):

	def __init__(self):
		self.transport = None
		super().__init__

	def connection_made(self,transport):
		print("Passthrough layer 1-Connection Made Client Side")
		self.transport = transport
		self.higherProtocol().connection_made(self.transport)

	def data_received(self,data):
		print("Passthrough layer 1-Data Received Client Side")
		self.higherProtocol().data_received(data)

	def connection_lost(self, exc):
		self.transport = None

class passthrough2(StackingProtocol):

	def __init__(self):
		self.transport = None
		super().__init__

	def connection_made(self,transport):
		print("Passthrough layer 2-Connection Made Client Side")
		self.transport = transport
		self.higherProtocol().connection_made(self.transport)

	def data_received(self,data):
		print("Passthrough layer 2-Data Received Client Side")
		self.higherProtocol().data_received(data)

	def connection_lost(self, exc):
		self.transport = None

f = StackingProtocolFactory(lambda: passthrough1(), lambda: passthrough2())
ptConnector = playground.Connector(protocolStack=f)
playground.setConnector("passthrough", ptConnector)
loop = asyncio.get_event_loop()
conn = EchoControl()
coro = playground.getConnector("passthrough").create_playground_connection(conn.buildProtocol, "20174.1.1.1", 101)
client = loop.run_until_complete(coro)
print("Echo Client Connected.")
loop.run_forever()
loop.close()
