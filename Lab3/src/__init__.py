import playground
from playground.network.common import StackingProtocolFactory

from .server import Serverfactory
from .client import Clientfactory

from .pls_client import PLSClientProtocol
from .pls_server import PLSServerProtocol


ClientFactory = StackingProtocolFactory(lambda: client.PEEPClientProtocol(), lambda: pls_client.PLSClientProtocol())
ServerFactory = StackingProtocolFactory(lambda: server.PEEPServerProtocol(), lambda: pls_server.PLSServerProtocol())

lab3_connector = playground.Connector(protocolStack=(ClientFactory, ServerFactory))
playground.setConnector("lab3_protocol1", lab3_connector)
