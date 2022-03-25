"""
This class is responsible for establishing a connection to the backend server and
forwarding the request and fetches the response .
"""


import socket
from servguard import logger





class Forwarder:
    """
    This class is responsible for sending the intercepted data to the requested server
    and sends back the response to the client.
    """

    def __init__(self,transport,timeout=5):
        """
        Args:
            data(bytes): Consists of the raw request.
        """



        socket.setdefaulttimeout(timeout)

        self.socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
        self.transport=transport

        # Initialize Logger

        self.logger = logger.ServGuardLogger(
            __name__,
            debug=True
        )


    def connect(self,host,server_map):

        """
        Extracts the host name and connects the socket to the host on port 80
        """

        self.host=host


        # Check whether the incoming Host is part of the backend server config

        if self.host in server_map.keys():
            host,port=server_map[host].split(":")

            try :
                {
                    self.socket.connect((host,int(port)))
                 }
            except Exception as e:
                       self.logger.log(
                           "Error:{}".format(e),
                           logtype="error"
                                       )
        else:

            self.logger.log(
                "Routing table not configured for Incoming HOST:{}".format(self.host),
                logtype="error"


            )
            self.transport.close();

    def handle_CONNECT(self,domain):
        try:

                self.socket.connect((domain,443))
        except Exception as e:
            print(e)


    def send_data(self,data):
        """
        Sends the data through the socket to the server
        """


        self.socket.sendall(data)

    def receive_data(self):

        """
        Data from the server (response) is returned to the interceptor.
        """


        response = b""

        while True:
            try:
                buf = self.socket.recv(1024)
                if not buf:
                    break
                else:
                    response += buf

            except Exception as e:
                break

        return response

    def close(self):

        self.socket.close();