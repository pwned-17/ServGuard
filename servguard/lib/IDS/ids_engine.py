#!/bin/python
from servguard.lib.IDS.recon_attack import DetectRecon
from servguard.lib.IDS.r2l_rules.r2l_engine import R2LEngine
from servguard import logger
import scapy.all as scapy
from servguard.lib.IDS.utils import *
import sys


class SecureTeaIDS(object):
    """SecureTeaIDS Class."""

    def __init__(self, cred=None, debug=None):
        """Initialize SecureTeaIDS.

        Args:
            cred (dict): Credentials for IDS
            debug (bool): Log on terminal or not

        Raises:
            None

        Returns:
            None
        """
        self.cred = cred

        # Initialize logger
        self.logger = logger.ServGuardLogger(
                __name__,
                debug=debug
        )

        # Check for root
        if check_root():

            # Create DetectRecon object
            self.recon_obj = DetectRecon(threshold=self.cred["threshold"],
                                         eligibility_threshold=self.cred["eligibility_threshold"],
                                         severity_factor=self.cred["severity_factor"],
                                         debug=debug)

            interface = self.cred["interface"]
            if interface and interface != "XXXX":
                self.interface = interface
            else:
                self.logger.log(
                    "Collecting interface",
                    logtype="info"
                )
                print("interface not found")

            # Create R2LEngine object
            self.r2l_rules = R2LEngine(debug=debug, interface=self.cred["interface"])
            self.logger.log(
                "SecureTea Intrusion Detection started",
                logtype="info"
            )
        else:
            self.logger.log(
                "Run as root",
                logtype="error"
            )
            sys.exit(1)

    def run(self, scapy_pkt):
        """
        Process the packet by passing it through various
        filters.

        - Reconnaissance attacks
        - R2L attacks

        Args:
            scapy_pkt (scapy_object): Packet to dissect and process

        Raises:
            None

        Returns:
            None
        """
        # Process the packet for reconnaissance detection
        self.recon_obj.run(scapy_pkt)
        # Process the packet for R2L attack detection
        self.r2l_rules.run(scapy_pkt)


    def start_ids(self):
        """
        Start SecureTea IDS.

        Args:
            None

        Raises:
            None

        Returns:
            None
        """
        # Start sniffing the network packets
        scapy.sniff(prn=self.run, store=0)
creds={"threshold":10,
       "eligibility_threshold":0.5,
        "severity_factor":0.9,
        "interface":'enp0s3'}
#obj=SecureTeaIDS(cred=creds,debug=True)
if __name__=="__main__":
    pass
    #obj.start_ids()