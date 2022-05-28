

import scapy.all as scapy
import time
from collections import OrderedDict
from servguard import logger
from servguard import alerter
from pymemcache.client import base
from servguard import log2sys

class DDoS(object):
    """Detect DDoS attacks."""

    def __init__(self, debug=False):
        """
        Initialize DDoS attack detection.

        Args:
            None

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
        # Initialize System Logger
        self.log2sys=log2sys.WafLogger(__name__,debug=debug)
        # memcached for state store
        self.client = base.Client(("localhost", 11211))
        # sack for Alerting
        self.alerter = alerter.Alert(debug=True)
        # Initial Flags for Alerts
        self.client.set("sisp", False)
        self.client.set("simp", False)
        self.client.set("misp", False)
        self.client.set("mimp", False)


        # Initialize empty dicts
        self.sisp = OrderedDict()
        self.simp = OrderedDict()
        self.misp = OrderedDict()
        self.mimp = OrderedDict()

        # Initialize threshold to 10000 packets / per second
        self._THRESHOLD = 100  # inter = 0.0001

    def classify_ddos(self, pkt):
        """
        Classify DDoS attacks into the following:
            - SISP (Single IP Single Port)
            - SIMP (Single IP Multiple Port)
            - MISP (Multiple IP Single Port)
            - MIMP (Multiple IP Multiple Port)

        Args:
            pkt (scapy_object): Packet to dissect and observe

        Raises:
            None

        Returns:
            None
        """
        if (pkt.haslayer(scapy.IP) and
            pkt.haslayer(scapy.TCP)):
            src_ip = pkt[scapy.IP].src
            dst_port = pkt[scapy.TCP].dport

            if self.sisp.get(src_ip) is None:
                # Packet from a new IP address
                self.sisp[src_ip] = {
                    "count": 1,
                    "ports": [dst_port],
                    "start_time": int(time.time())
                }
            else:
                # Increment count
                current_count = self.sisp[src_ip]["count"]
                self.sisp[src_ip]["count"] = current_count + 1

                if (dst_port not in \
                    self.sisp[src_ip]["ports"]):
                    self.sisp[src_ip]["ports"].append(dst_port)
                    # Move to simp dict
                    self.simp[src_ip] = self.sisp[src_ip]
                    del self.sisp[src_ip]

        # Detect intrusion
        self.detect_sisp()
        self.detect_simp()
        self.detect_misp()
        self.detect_mimp()

    def detect_simp(self):
        """
        Detect SIMP (Single IP Multiple Port) DDoS attack.

        Args:
            None

        Raises:
            None

        Returns:
            None
        """
        # Check intrusion for simp
        for ip in self.simp.keys():
            count = self.simp[ip]["count"]
            len_port = len(self.simp[ip]["ports"])
            start_time = int(self.simp[ip]["start_time"])
            current_time = int(time.time())
            delta_time = int(current_time - start_time)

            try:
                calc_count_threshold = int(count / delta_time)
            except ZeroDivisionError:
                calc_count_threshold = int(count)
            try:
                calc_portlen_threshold = int(len_port / delta_time)
            except ZeroDivisionError:
                calc_portlen_threshold = int(len_port)

            if ((calc_count_threshold > self._THRESHOLD or
                calc_portlen_threshold > self._THRESHOLD) and self.client.get("simp").decode("utf-8")=="True"):
                self.logger.log(
                    "Possible Single IP Multiple Port DDoS attack",
                    logtype="warning"
                )
            if ((calc_count_threshold > self._THRESHOLD or
                 calc_portlen_threshold > self._THRESHOLD) and self.client.get("simp").decode("utf-8") =="False"):
                self.client.set("simp", True)

                alert_msg = {"Origin": "IDS",
                             "IP": ip,
                             "Incident": "Possible Single IP Multiple Port DDoS attack."
                             }

                self.alerter.run(alert_msg)
                self.logger.log(
                    "Possible Single IP Multiple Port DDoS attack",
                    logtype="warning"
                )
                self.log2sys.write_log("Possible Single IP Multiple Port DDoS attack")

    def detect_sisp(self):
        """
        Detect SISP (Single IP Single Port) DDoS attack.

        Args:
            None

        Raises:
            None

        Returns:
            None
        """
        for ip in self.sisp.keys():
            count = self.sisp[ip]["count"]
            start_time = self.sisp[ip]["start_time"]
            current_time = int(time.time())
            delta_time = int(current_time - start_time)

            try:
                calc_threshold = int(count / delta_time)
            except ZeroDivisionError:
                calc_threshold = int(count)

            if ((calc_threshold > self._THRESHOLD) and self.client.get("sisp").decode("utf-8") == "True"):
                self.logger.log(
                    "Possible Single IP Single Port DDoS attack detected",
                    logtype="warning"
                )
            if ((calc_threshold > self._THRESHOLD) and self.client.get("sisp").decode("utf-8") == "False"):
                self.client.set("sisp", True)
                alert_msg = {"Origin": "IDS",
                             "IP": ip,
                             "Incident": "Possible Single IP Single Port DDoS attack."
                             }

                self.alerter.run(alert_msg)
                self.logger.log(
                    "Possible Multiple IP Single Port DDoS attack detected",
                    logtype="warning"
                )
                self.log2sys.write_log("Possible Multiple IP Multiple Port DDoS attack")

    def detect_misp(self):
        """
        Detect MISP (Multiple IP Single Port) DDoS attack.

        Args:
            None

        Raises:
            None

        Returns:
            None
        """
        # Check intrusion for misp
        for ip in self.sisp.keys():
            port = self.sisp[ip]["ports"][0]

            if self.misp.get(port) is not None:
                self.misp[port]["count"] = self.misp[port]["count"] + 1
            else:
                self.misp[port] = {
                    "count": 1,
                    "start_time": int(time.time())
                }

        for port in self.misp.keys():
            count = int(self.misp[port]["count"])
            start_time = self.misp[port]["start_time"]
            current_time = int(time.time())
            delta_time = int(current_time - start_time)

            try:
                calc_threshold = int(count / delta_time)
            except ZeroDivisionError:
                calc_threshold = int(count)

            if ((calc_threshold > self._THRESHOLD) and self.client.get("misp").decode("utf-8")=="True"):
                self.logger.log(
                    "Possible Multiple IP Single Port DDoS attack detected",
                    logtype="warning"
                )
            if ((calc_threshold > self._THRESHOLD) and self.client.get("misp").decode("utf-8") == "False"):
                self.client.set("misp", True)

                alert_msg = {"Origin": "IDS",
                             "IP": "Multiple IPs ,Port:{}".format(port),
                             "Incident": "Possible Multiple IP Single Port DDoS attack."
                             }

                self.alerter.run(alert_msg)
                self.logger.log(
                    "Possible Multiple IP Single Port DDoS attack detected",
                    logtype="warning"
                )
                self.log2sys.write_log("Possible Multiple IP Single Port DDoS attack")

    def detect_mimp(self):
        """
        Detect MIMP (Multiple IP Multiple Port) DDoS attack.

        Args:
            None

        Raises:
            None

        Returns:
            None
        """
        if len(self.simp) != 0:
            start_ip = [key for key in self.simp.keys()][0]
            end_ip = [key for key in self.simp.keys()][-1]

            start_time = int(self.simp[start_ip]["start_time"])
            end_time = int(self.simp[end_ip]["start_time"])
            delta_time = int(end_time - start_time)

            try:
                calc_threshold = len(self.simp) / delta_time
            except ZeroDivisionError:
                calc_threshold = len(self.simp)

            if ((calc_threshold > self._THRESHOLD) and self.client.get("mimp").decode("utf-8") == "True"):
                self.logger.log(
                    "Possible Multiple IP Single Port DDoS attack detected",
                    logtype="warning"
                )
            if ((calc_threshold > self._THRESHOLD) and self.client.get("mimp").decode("utf-8") == "False"):
                self.client.set("mimp", True)

                alert_msg = {"Origin": "IDS",
                             "IP": "Multiple IPs",
                             "Incident": "Possible Multiple IP Multiple Port DDoS attack."
                             }

                self.alerter.run(alert_msg)
                self.logger.log(
                    "Possible Multiple IP Multiple Port DDoS attack detected",
                    logtype="warning"
                )
                self.log2sys.write_log("Possible Multiple IP Multiple Port DDoS attack")
