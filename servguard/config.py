"""
Module responsible for Importing all the configuration from the config file

"""
import json
import os

from servguard import logger

class Configuration():

    def __init__(self,path):
        """
        Initialize the arguments required for reading configuration from a file

        Args: path
        Desc: The path of the config file
        """
        self.path=path

        #Initialize Logger
        self.logger=logger.ServGuardLogger(
            __name__,
            debug=True
        )
    def read_config(self):


        """
        Reads the config file and converts into key pair values

        Returns:
            creds(dictionary): Contains all the required config files for servguard.
        """


        if os.path.exists(self.path):
            with open(self.path,'r') as f:
                self.creds=json.load(f)

        else:
            self.logger.log(
                "Config Path does not exist",
                logtype="error"
            )
        return self.creds

