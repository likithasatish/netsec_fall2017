
import sys

from playground.network.packet import PacketType

from playground.network.packet.fieldtypes import STRING,BUFFER,INT64,BOOL

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


