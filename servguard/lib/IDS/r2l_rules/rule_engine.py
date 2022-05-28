from servguard.lib.IDS.r2l_rules.arp_spoof import ARPCache

from servguard.lib.IDS.r2l_rules.ddos import DDoS

from servguard.lib.IDS.r2l_rules.ping_of_death import PingOfDeath
from servguard.lib.IDS.r2l_rules.macflood import MAC
from servguard.lib.IDS.r2l_rules.land_dos import LandDOS
from servguard.lib.IDS.r2l_rules.syn_flood import SynFlood



class R2LEngine(object):
    """R2LEngine class."""

    def __init__(self, debug=False, interface=None):
        """
        Initialize R2LEngine.

        Args:
            interface (str): Name of interface on which to monitor
            debug (bool): Log on terminal or not

        Raises:
            None

        Returns:
            None
        """
        # Create objects of all the imported class
        self.arp_spoof = ARPCache(debug=debug)

        self.ping_of_death = PingOfDeath(debug=debug)

        self.ddos = DDoS(debug=debug)
        self.macflood=MAC(debug=debug)
        self.land=LandDOS(debug=debug)
        self.syn_flood=SynFlood(debug=debug)

    def run(self, pkt):
        """
        Pass the packet through all the
        filter rules.

        Args:
            pkt (scapy_object): Packet to dissect and observe

        Raises:
            None

        Returns:
            None
        """
        # Pass the packets
        self.arp_spoof.proces_packet(pkt)

        self.ping_of_death.detect(pkt)
        self.ddos.classify_ddos(pkt)
        self.macflood.detect_cam(pkt)
        self.land.detect_land_dos(pkt)
        self.syn_flood.detect_syn_flood(pkt)
