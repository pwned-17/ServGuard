"""
Logging Module to Write Log to Server
"""

from servguard import logger
import time
import os
import re


class WafLogger(logger.ServGuardLogger):

    def __init__(self, modulename, debug=False):


        self._PATH = "/etc/servguard/waf.log"
        if os.path.exists(self._PATH):
            pass
        else:
           try :
               os.mkdir("/etc/servguard/")
           except Exception as E:
               print(E)



        try:
            f_create = open("/etc/servguard/waf.log", "a")
            f_create2=open("/etc/servguard/ids.log","a")
            f_create.close()
            f_create2.close()
        except Exception as e:
            print(e)

        logger.ServGuardLogger.__init__(self, modulename, debug)

    def write_log(self, message):
        if re.search("servguard.lib.WAF",self.modulename):
            with open(self._PATH, "a") as f:
                LEGEND = '[' + self.modulename + ']' + ' [' + \
                         str(time.strftime("%Y-%m-%d %H:%M")) + '] '
                message = LEGEND + message + "\n"
                f.write(message)
                f.close()
        else:
            with open("/etc/servguard/ids.log", "a") as f:
                LEGEND = '[' + self.modulename + ']' + ' [' + \
                         str(time.strftime("%Y-%m-%d %H:%M")) + '] '
                message = LEGEND + message + "\n"
                f.write(message)
                f.close()


