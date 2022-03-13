

import scapy.all as scapy
from servguard import logger


class LandAttack(object):
    """LandAttack class."""

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

    def detect_land_attack(self, pkt):
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
                (source_port == dest_port)):
                self.logger.log(
                    "Possible land attack detected.",
                    logtype="warning"
                )
