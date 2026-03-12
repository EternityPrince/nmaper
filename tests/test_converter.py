from __future__ import annotations

import unittest

from src.converter import collect_open_ports_by_host
from src.parser import parse_nmap_xml

DISCOVERY_XML = """<?xml version="1.0"?>
<nmaprun
  scanner="nmap"
  args="nmap -sS 192.168.0.0/24 -oX -"
  startstr="Thu Mar 12 19:50:00 2026"
  version="7.98"
>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="reset"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class ConverterTests(unittest.TestCase):
    def test_collect_open_ports_by_host(self) -> None:
        parsed = parse_nmap_xml(DISCOVERY_XML)

        self.assertEqual(
            collect_open_ports_by_host(parsed),
            {
                "192.168.0.1": [22],
                "192.168.0.2": [443],
            },
        )


if __name__ == "__main__":
    unittest.main()
