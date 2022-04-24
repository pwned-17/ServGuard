""" Core module responsible for Loading Configuration and Starting WAF and IDS"""


from config import Configuration
from servguard.lib.WAF import waf_engine
from servguard.lib.IDS import ids_engine
from servguard import logger

import sys
import multiprocessing

class ServGuard():

    def __init__(self,path):
        #config path

        self.path=path
        if self.path !=None:

            obj=Configuration(self.path)
            self.creds=obj.read_config()


        # initialize logger

        self.logger=logger.ServGuardLogger(__name__,debug=True)

        self.WAF=False
        self.IDS=False
        self.process_pool = []

    def create_object(self):

        self.mode=self.creds["Servguard_Mode"]

        if self.mode==0:

            self.WAF=True
            self.waf_obj=waf_engine.ServGuardWaf(creds=self.creds["WAF"])

            self.logger.log(
                "Initializing ServGuard Web Application Firewall",
                logtype="info"
            )
        elif self.mode==1:
            self.IDS=True

            self.ids_obj=ids_engine.ServGuardIds(cred=self.creds["IDS"],debug=True)

            self.logger.log(
                "Initializing ServGuard Intrusion Detection  System",
                logtype="info"
            )

        elif self.mode==2:

            self.WAF=True

            self.waf_obj = waf_engine.ServGuardWaf(creds=self.creds["WAF"])

            self.logger.log(
                "Initializing ServGuard Web Application Firewall",
                logtype="info"
            )

            self.IDS=True
            self.ids_obj = ids_engine.ServGuardIds(cred=self.creds["IDS"], debug=True)

            self.logger.log(
                "Initializing ServGuard Intrusion Detection  System",
                logtype="info"
            )

        else :
            self.logger.log(
                "Error Please Configure ServGuard Modes ",
                logtype="error"
            )
            sys.exit()

    def create_process(self):

        if self.WAF and self.IDS:
            waf_process=multiprocessing.Process(target=self.waf_obj.run_server())

            ids_process=multiprocessing.Process(target=self.ids_obj.start_ids())
            self.process_pool.append(ids_process)
            self.process_pool.append(waf_process)

    def start_ServGuard(self):

        self.create_object()

        if self.mode==2:
            self.create_process()
            try:
                for process in self.process_pool:
                    process.start()
                for process in self.process_pool:
                    process.join()
            except KeyboardInterrupt:
                for process in self.process_pool:
                    process.terminate()

                self.logger.log("Shutting Down ServGuard",logtype="info")
                sys.exit()
            except Exception as E:
                self.logger.log(E,logtype="error")

        elif self.mode==0:
            try:
                self.waf_obj.run_server()
                self.logger.log("Started Web Application Firewall",logtype="info")
            except KeyboardInterrupt:

                self.logger.log("Shutting Down ServGuard", logtype="info")
                sys.exit()
            except Exception as E:
                self.logger.log(E, logtype="error")

        elif self.mode==1:
            try:
                if __name__=="__main__":
                    self.logger.log("Started  Intrusion Detection System", logtype="info")
                    self.ids_obj.start_ids()

            except KeyboardInterrupt:

                self.logger.log("Shutting Down ServGuard", logtype="info")
                sys.exit()
            except Exception as E:
                self.logger.log(E, logtype="error")

obj=ServGuard(path="../servguard.conf")
obj.start_ServGuard()







