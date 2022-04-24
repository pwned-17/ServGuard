
import asyncio
import uvloop
import nest_asyncio


from servguard import logger
from servguard.lib.WAF.request_handler import HTTP




class ServGuardWaf():
    """
     A class that starts the WAF  server
    """

    def __init__(self, creds):
        """
         Initialize host and port for listening
        """
        self.creds=creds
        self.listen_ip =creds["listen_ip"]
        self.listen_port =creds["listen_port"]
        #Memcached client




        # Initialize logger

        self.logger = logger.ServGuardLogger(
            __name__,
            debug=True
        )

    def run_server(self):

        try:
            asyncio.run(self.start())

            # asyncio.get_event_loop().run_until_complete(self.start())

        except Exception as e:
            print(e)
        finally:

            self.server.close()

            self.loop.close()

    async def start(self):

        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        self.loop = asyncio.get_event_loop()
        nest_asyncio.apply(self.loop)
        self.server = await self.loop.create_server(

            lambda: HTTP(creds=self.creds), host=self.listen_ip, port=self.listen_port,start_serving=False,backlog=1000
        )

        ip, port = self.server.sockets[0].getsockname()
        self.logger.log(

            "Started WAF server on {}:{} ".format(ip, port),
            logtype="info"
        )

        await self.server.serve_forever()



#helo
#creds={"listen_ip":"0.0.0.0",
       #"listen_port":5555,
       #"server_map":{"localhost":"localhost:5000","127.0.0.1:5555":"127.0.0.1:2000","192.168.246.156:5555":"127.0.0.1:2000"},
       #"debug":True,
       #"mode":0,
       #"secure_headers":0}
#waf_obj=ServGuardWaf(creds)
#waf_obj.run_server()