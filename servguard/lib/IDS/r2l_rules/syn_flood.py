"""
Module to Detect Syn Flood attack

"""

import scapy.all as scapy
import time
from servguard import logger
from servguard import  alerter
from pymemcache.client import base
from servguard import log2sys


class SynFlood(object):
    """SynFlood Class."""

    def __init__(self, debug=False):
        """
        Initialize SynFlood.
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
        self.client.set("syn", False)
        # Initialize SYN dictionary
        self.syn_dict = {}

        # Set threshold to 1000 SYN packets / per second
        self._THRESHOLD = 1000  # inter = 0.001

    def detect_syn_flood(self, pkt):
        """
        Detect SYN flood attack.
        Args:
            pkt (scapy_object): Packet to dissect and observe
        Raises:
            None
        Returns:
            None
        """
        if not pkt.haslayer(scapy.IP) or not pkt.haslayer(scapy.TCP):
            return

        flag = pkt[scapy.TCP].flags
        source_ip = pkt[scapy.IP].src

        if flag == "S":  # SYN flag
            if self.syn_dict.get(source_ip) is None:
                # If new IP address
                self.syn_dict[source_ip] = {
                    "start_time": time.time(),
                    "count": 1
                }
            else:
                count = self.syn_dict[source_ip]["count"]
                self.syn_dict[source_ip]["count"] = count + 1
        if flag == "A" and self.syn_dict.get(source_ip) is not None:
            # Handshake completed, delete the IP entry (not suspicious)
            del self.syn_dict[source_ip]

        # Detect intrusion
        self.calc_intrusion()

    def calc_intrusion(self):
        """
        Detect intrusion by comparing threshold
        ratios.
        Args:
            None
        Raises:
            None
        Returns:
            None
        """
        if len(self.syn_dict) == 0:  # If syn dict is not empty
            return
        start_ip = [ip for ip in self.syn_dict.keys()][0]
        start_time = self.syn_dict[start_ip]["start_time"]
        current_time = time.time()
        delta_time = int(current_time - start_time)

        size_of_syn_dict = len(self.syn_dict)

        try:
            calc_threshold = int(size_of_syn_dict / delta_time)
        except ZeroDivisionError:
            calc_threshold = int(size_of_syn_dict)

        if (calc_threshold >= self._THRESHOLD):
            self.logger.log(
                "Possible SYN flood attack detected.",
                logtype="warning"
            )
        if ((calc_threshold > self._THRESHOLD) and self.client.get("syn").decode("utf-8") == "True"):
            self.logger.log(
                "Possible SYN Flood attack detected",
                logtype="warning"
            )
            self.log2sys.write_log("Possible SYN  Flood attack detected")

        if ((calc_threshold > self._THRESHOLD) and self.client.get("syn").decode("utf-8") == "False"):
            self.client.set("syn", True)

            alert_msg = {"Origin": "IDS",
                         "IP": start_ip,
                         "Incident": "Possible SYN Flood attack detected"
                         }

            self.alerter.run(alert_msg)
            self.logger.log(
                "Possible SYN Flood attack detected",
                logtype="warning"
            )
            self.log2sys.write_log("Possible SYN Flood attack detected")