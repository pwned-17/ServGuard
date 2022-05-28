import scapy.all as scapy
import time
from servguard import logger
from servguard import log2sys
from pymemcache.client import base
from servguard import alerter



class MAC(object):
    """MAC Class."""

    def __init__(self, debug=False):
        """
        Initialize MAC FLood class.
        Detect MAC FLOOD attack.
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
        self.client.set("mac", False)
        # Initialize time
        self.start_time = None
        # Initialize cam_attack list
        self.cam_list = []
        # Initialize threshold to 256 MAC address / 6 second
        self._THRESHOLD = 256 / 6  # inter = 0.0234

    def detect_cam(self, pkt):
        """
        Detect CAM Table attack.
        Args:
            pkt (scapy_object): Packet to observe and dissect
        Raises:
            None
        Returns:
            None
        """
        if (pkt.haslayer(scapy.Ether)):
            source_mac = pkt[scapy.Ether].src

            if self.start_time is None:
                self.start_time = int(time.time())

            if source_mac not in self.cam_list:
                self.cam_list.append(source_mac)

            self.calc_intrusion()

    def calc_intrusion(self):
        """
        Calculate CAM attack observed ratio and
        compare it with the set threshold to detect
        intrusion.
        Args:
            None
        Returns:
            None
        Raises:
            None
        """
        total_cam = len(self.cam_list)
        current_time = int(time.time())
        delta_time = int(current_time - self.start_time)

        try:
            calc_threshold = int(total_cam / delta_time)
        except ZeroDivisionError:
            calc_threshold = int(total_cam)

        if ((calc_threshold > self._THRESHOLD) and self.client.get("mac").decode("utf-8")=="True"):
            self.logger.log(
                "Possible Mac Flood attack detected",
                logtype="warning"
            )
            self.log2sys.write_log("Possible Mac Flood attack detected")

        if ((calc_threshold > self._THRESHOLD) and self.client.get("mac").decode("utf-8")=="False"):
            self.client.set("mac", True)

            alert_msg = {"Origin": "IDS",
                         "Total MAC":total_cam ,
                         "Incident": "Possible MAC Flood attack detected"
                         }

            self.alerter.run(alert_msg)
            self.logger.log(
                "Possible Mac Flood attack detected",
                logtype="warning"
            )
            self.log2sys.write_log("Possible Mac Flood attack detected")