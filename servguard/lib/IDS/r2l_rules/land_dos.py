import scapy.all as scapy
from servguard import logger
from servguard import log2sys
from pymemcache.client import base
from servguard import alerter



class LandDOS(object):
    """LandDOS class."""

    def __init__(self, debug=False):
        """
        Initialize LandAttack class.
        Args:
            debug (bool): Log on terminal or not
        Raises:
            None
        Returns:
            None
        """
        # Initialize logger
        self.logger = logger.ServGuardLogger(
                __name__,
                debug=debug
        )
        # Initilaize Logging to System
        self.log2sys = log2sys.WafLogger(__name__, debug=debug)
        # memcached for state store
        self.client = base.Client(("localhost", 11211))
        # sack for Alerting
        self.alerter = alerter.Alert(debug=True)
        # Initial Flags for Alerts
        self.client.set("land", False)


    def detect_land_dos(self, pkt):
        """
        Detect land attack by observing source,
        destination IP & ports.
        Args:
            pkt (scapy_object): Packet to dissect and observe
        Raises:
            None
        Returns:
            None
        """
        if (pkt.haslayer(scapy.IP) and
            pkt.haslayer(scapy.TCP)):

            source_ip = pkt[scapy.IP].src
            dest_ip = pkt[scapy.IP].dst

            source_port = pkt[scapy.TCP].sport
            dest_port = pkt[scapy.TCP].dport

            if ((source_ip == dest_ip) and
                (source_port == dest_port) and self.client.get("land").decode("utf-8")=="True"):
                self.logger.log(
                    "Possible land dos detected.",
                    logtype="warning"
                )
                self.log2sys.write_log("Possible land dos detected.")

            if ((source_ip == dest_ip) and
                (source_port == dest_port) and self.client.get("land").decode("utf-8")=="False"):
                self.client.set("land",True)

                alert_msg = {"Origin": "IDS",
                             "IP": source_ip,
                             "Incident": "Possible land dos detected"
                             }

                self.alerter.run(alert_msg)
                self.logger.log(
                    "Possible land dos detected.",
                    logtype="warning"
                )
                self.log2sys.write_log("Possible land dos detected.")
