
import asyncio

from servguard import logger



class HTTP(asyncio.Protocol):
    """
       A class that handles incoming HTTP request
       Parses the request and sends back the response to the client.
    """

    def __init__(self,creds):

        self.debug=creds["debug"]
        self.server_map=creds["server_map"]
        self.mode=creds["mode"]

        #Initialize Logger

        self.logger=logger.ServGuardLogger(__name__,
                                           debug=self.debug)



    def connection_made(self, transport):
        """
          asyncio default method that gets called on every request.
          Args:
          transport(object): Instance of the current connection.
        """
        self.transport = transport
        self.rhost,self.rport=self.transport.get_extra_info("peername")
        print(self.rhost)
        print(self.rport)

    def data_received(self, data):

        """
         Incoming client data
         Args:
             data(bytes):Has the request headers and body

        """















    def close_transport(self):

       """
          Close the current instance of the transport for every successful session.
       """
       self.transport.close();