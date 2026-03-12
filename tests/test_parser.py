from __future__ import annotations

import unittest

from src.parser import parse_nmap_xml

DETAIL_XML = """<?xml version="1.0"?>
<nmaprun
  scanner="nmap"
  args="nmap -A -O 192.168.0.1 -oX -"
  startstr="Thu Mar 12 19:51:00 2026"
  version="7.98"
>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.0.1" addrtype="ipv4"/>
    <address addr="AC:15:A2:85:C5:71" addrtype="mac" vendor="TP-Link Limited"/>
    <hostnames>
      <hostname name="router.local"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="53">
        <state state="open" reason="syn-ack"/>
        <service name="domain" product="dnsd" version="1.0" method="probed" conf="10">
          <cpe>cpe:/a:example:dnsd:1.0</cpe>
        </service>
        <script id="dns-nsid" output="bind.version: v1.0.0"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.X" accuracy="92" line="12345"/>
      <osfingerprint fingerprint="TCP/IP fingerprint"/>
    </os>
    <hostscript>
      <script id="uptime" output="System uptime">
        <elem key="seconds">3600</elem>
      </script>
    </hostscript>
    <trace>
      <hop ttl="1" ipaddr="192.168.0.1" rtt="15.46" host="router.local"/>
    </trace>
    <uptime seconds="3600"/>
    <distance value="1"/>
  </host>
  <runstats>
    <finished timestr="Thu Mar 12 19:51:20 2026" elapsed="20.0"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
"""


class ParserTests(unittest.TestCase):
    def test_parse_nmap_xml_extracts_detail_fields(self) -> None:
        parsed = parse_nmap_xml(DETAIL_XML)

        self.assertEqual(parsed.version, "7.98")
        self.assertEqual(parsed.stats.total_hosts, 1)
        host = parsed.hosts[0]
        self.assertEqual(host.primary_ip, "192.168.0.1")
        self.assertEqual(host.mac_address, "AC:15:A2:85:C5:71")
        self.assertEqual(host.mac_vendor, "TP-Link Limited")
        self.assertEqual(host.hostnames, ["router.local"])
        self.assertEqual(host.distance_hops, 1)
        self.assertEqual(host.uptime_seconds, 3600)
        self.assertEqual(host.os_matches[0].name, "Linux 5.X")
        self.assertEqual(host.ports[0].service_name, "domain")
        self.assertEqual(host.ports[0].scripts[0].script_id, "dns-nsid")
        self.assertEqual(host.host_scripts[0].elements["seconds"], "3600")
        self.assertEqual(host.trace_hops[0].ttl, 1)


if __name__ == "__main__":
    unittest.main()
