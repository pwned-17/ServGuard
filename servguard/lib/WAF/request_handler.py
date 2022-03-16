
import asyncio

from servguard import logger
from servguard.lib.WAF import analyzer
from utils import *



class HTTP(asyncio.Protocol):
    """
       A class that handles incoming HTTP request
       Parses the request and sends back the response to the client.
    """

    def __init__(self,creds):

        self.debug=creds["debug"]
        self.server_map=creds["server_map"]
        self.mode=creds["mode"]

        # analyzer class



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


    def data_received(self, data):

        """
         Incoming client data
         Args:
             data(bytes):Has the request headers and body

        """

        self.data=data

        # Parse Data for further Analysis

        self.parsed_data=RequestParser(self.data)
        self.mlanalyzer = analyzer.MlAnalyzer(self.parsed_data.path)

        # GET REQUEST

        if self.parsed_data.command=="GET":
            self.mlanalyzer.loadmodel()
            self.value=self.mlanalyzer.predictor()

            if self.value[0]=="cmdi":
                self.logger.log(
                    "Command Injection Detected from {}:{}".format(self.rhost,self.rport),
                    logtype="warning"
                )
            if self.value[0]=="valid":
                self.logger.log(
                    "Valid Request from  from {}:{} on path {}".format(self.rhost, self.rport,self.parsed_data.path),
                    logtype="info"
                )





        # POST REQUEST

        elif self.parsed_data.command=="POST":
            pass


        # CONNECT REQUEST

        elif self.parsed_data.command=="CONNECT":
            pass



        # OTHER REQUESTS

        else:
            pass














    def close_transport(self):

       """
          Close the current instance of the transport for every successful session.
       """
       self.transport.close();