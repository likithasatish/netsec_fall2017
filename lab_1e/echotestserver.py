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

class passthrough1(StackingProtocol):

	def __init__(self):
		self.transport = None
		super().__init__

	def connection_made(self,transport):
		print("Passthrough layer 1-Connection Made Server Side")
		self.transport = transport
		self.higherProtocol().connection_made(self.transport)


	def data_received(self,data):
		print("Passthrough layer 1-Data Received Server Side")
		self.higherProtocol().data_received(data)

	def connection_lost(self, exc):
		self.transport = None

class passthrough2(StackingProtocol):

	def __init__(self):
		self.transport = None
		super().__init__

	def connection_made(self,transport):
		print("Passthrough layer 2-Connnection Made Server Side")
		self.transport = transport
		self.higherProtocol().connection_made(self.transport)


	def data_received(self,data):
		print("Passthrough layer 2-Data Recieved Server Side")
		self.higherProtocol().data_received(data)

	def connection_lost(self, exc):
		self.transport = None

f = StackingProtocolFactory(lambda: passthrough1(), lambda: passthrough2())
ptConnector = playground.Connector(protocolStack=f)
playground.setConnector("passthrough", ptConnector)
loop = asyncio.get_event_loop()
coro = playground.getConnector("passthrough").create_playground_server(lambda: EchoServerProtocol(), 101)
server = loop.run_until_complete(coro)
print("Echo Server Started ")
loop.run_forever()
loop.close()
