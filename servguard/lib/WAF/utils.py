from http.server import BaseHTTPRequestHandler

import io


class RequestParser(BaseHTTPRequestHandler):
    """
       Handler to parse the request data from client
    """
    def __init__(self,data):
        """
        Args:
            data(bytes):Data containing the Request From the Client
        """
        self.rfile=io.BytesIO(data)
        self.raw_requestline=self.rfile.readline()

        self.parse_request()


    def get_body(self):
        self.len=int(self.headers.get('Content-Length'))
        return self.rfile.read(self.len)



    def send_header(self, keyword,value):
        print(keyword,value)


    def send_error(self, code, message):
        """
         Called by the BasseHTTPRequestHandler when there is an error
         Args:
             code(int): The error code
             message(string): The error Messages that should be displayed
        """
        self.ecode=code;
        self.error_message=message;