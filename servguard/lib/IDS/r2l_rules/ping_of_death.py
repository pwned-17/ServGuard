
import scapy.all as scapy
from servguard import logger
from servguard import log2sys
from pymemcache.client import base
from servguard import alerter


class PingOfDeath(object):
    """PingOfDeath class."""

    def __init__(self, debug=False):
        """
        Initialize PingOfDeath.

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
        self.client.set("pod", False)

        # Initialize threshold
        self._THRESHOLD = 60



    def detect(self, pkt):
        """
        Detect ping of death attack
        by calculating load threshold.

        Args:
            pkt (scapy_object): Packet to dissect and observe

        Raises:
            None

        Returns:
            None
        """
        if (pkt.haslayer(scapy.IP) and
            pkt.haslayer(scapy.ICMP)):
            # If packet has load
            if pkt.haslayer(scapy.Raw):

                load_len = len(pkt[scapy.Raw].load)

                if ((load_len >= self._THRESHOLD) and self.client.get("pod").decode("utf-8")=="True"):
                    source_ip = pkt[scapy.IP].src
                    msg = "Possible ping of death attack detected " \
                          "from: {}".format(source_ip)
                    self.logger.log(
                        msg,
                        logtype="warning"
                    )
                    self.log2sys.write_log(msg)
                if ((load_len >= self._THRESHOLD) and self.client.get("pod").decode("utf-8")=="False"):
                    source_ip = pkt[scapy.IP].src
                    self.client.set("pod", True)

                    alert_msg = {"Origin": "IDS",
                                 "IP": source_ip,
                                 "Incident": "Possible ping of death attack detected"
                                 }

                    self.alerter.run(alert_msg)
                    msg = "Possible ping of death attack detected " \
                          "from: {}".format(source_ip)
                    self.logger.log(
                        msg,
                        logtype="warning"
                    )
                    self.log2sys.write_log(msg)

