import sys
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import STRING,BUFFER,INT64,BOOL

class initiateconnection(PacketType):
    DEFINITION_IDENTIFIER = "lab.client1.initiateconection"
    DEFINITION_VERSION = "1.0"

class authenticationmessage(PacketType):
    DEFINITION_IDENTIFIER = "lab.server1.authenticationmessage"
    DEFINITION_VERSION = "2.0"

    FIELDS = [
        ("imageID",INT64),
        ("pixelSequence",INT64)
        ]

class requestvalidation(PacketType):
    DEFINITION_IDENTIFIER = "lab.client2.requestvalidation"
    DEFINITION_VERSION = "3.0"

    FIELDS = [
            ("imageID",INT64),
            ("answer",STRING)
            ]

class validate(PacketType):
    DEFINITION_IDENTIFIER = "lab.server2.validate"
    DEFINITION_VERSION = "4.0"

    FIELDS = [
            ("imageID",INT64),
            ("boo",BOOL)
            ]

def unittest():
    packet1 = initiateconnection()
    packet2 = authenticationmessage()
    packet3 = requestvalidation()
    packet4 = validate()

    packet2.imageID = 7
    packet2.pixelSequence = 100111111001
    packet3.imageID = 7
    packet3.answer = "H"
    packet4.imageID = 7
    packet4.boo = True

    packet1s = packet1.__serialize__()
    packet1d = initiateconnection.Deserialize(packet1s)
    if (packet1 == packet1d):
        print ("packet1 works")

    packet2s = packet2.__serialize__()
    packet2d = authenticationmessage.Deserialize(packet2s)
    if (packet2 == packet2d):
        print ("packet2 works")

    packet3s = packet3.__serialize__()
    packet3d = requestvalidation.Deserialize(packet3s)
    if (packet3 == packet3d):
        print ("packet3 works")

    packet4s = packet4.__serialize__()
    packet4d = validate.Deserialize(packet4s)
    if (packet4 == packet4d):
        print ("packet4 works")

    combinepackets = packet1.__serialize__() + packet2.__serialize__() + packet3.__serialize__() + packet4.__serialize__()
    print (combinepackets)
    deserializer = PacketType.Deserializer()
    while len(combinepackets) > 0:
        subpacket, combinepackets = combinepackets[:10], combinepackets[10:]
        deserializer.update(subpacket)
        print ("chunk of combined packets")
        print (subpacket)
        print ("original combined packets")
        print (combinepackets)

    for packet in deserializer.nextPackets():
        print ("packet received")
        if packet == packet1:
            print ("packet1 using deserializer")
        elif packet == packet2:
            print ("packet2 using deserializer")
        elif packet == packet3:
            print ("packet3 using deserializer")
        elif packet == packet4:
            print ("packet4 using deserializer")

if __name__ == "__main__":
    unittest()




 
