# KNXnet/IP - OIDA `--gateway-scan` fingerprint

Detection content for the OIDA KNX gateway scan:

```bash
oida knx 127.0.0.1 -p 3671 --gateway-scan --tcp
```

Reference: OIDA 1.0.6 (`oida-ics[knx]`, xknx), against the OIDA mock KNXnet/IP
gateway (Calimero) on 127.0.0.1:3671 with emulated BCU devices 1.1.1-1.1.5 and
1.1.10. Reference capture: `oida_knx_gateway_scan.pcapng` (3256 packets,
captured on `lo`, linktype EN10MB so Suricata can replay it offline).

For the full `oida knx` command surface, see the protocol capability map in
[`../README.md`](../README.md). This page covers only the `--gateway-scan`
fingerprint and its Suricata rules.

## What `--gateway-scan` does

1. Opens a KNXnet/IP **TCP tunnel** to the gateway: `CONNECT_REQUEST`
   (0x0205), `CONNECT_RESPONSE` (0x0206), then `CONNECTIONSTATE`
   (0x0207/0x0208) keepalives.
2. Sweeps **255 individual addresses** (1.1.1-1.1.255) over the tunnel: one
   `TUNNELING_REQUEST` (0x0420) per address, carrying a cEMI `L_Data.req`
   with APCI `0x0080` (`A_DeviceDescriptor_Read`).
3. Queries the gateway itself with `DESCRIPTION_REQUEST` (0x0203): friendly
   name, MAC, serial, KNX address, supported services.
4. Scans for KNX/IP gateways via **multicast** `SEARCH_REQUEST` (0x0201) to
   224.0.23.12:3671.

KNX has no encryption and no authentication: every frame is plaintext, so the
whole behaviour is visible on the wire.

## Observed frame sequence

The KNXnet/IP header is 6 bytes: `06 10 <service type:2> <total length:2>`.

| Service | Code | Role |
| --- | --- | --- |
| SEARCH_REQUEST | `0x0201` | gateway discovery, UDP multicast 224.0.23.12:3671 |
| DESCRIPTION_REQUEST | `0x0203` | gateway information (UDP unicast in this capture) |
| CONNECT_REQUEST | `0x0205` | open the TCP tunnel |
| CONNECTIONSTATE_REQ/RESP | `0x0207`/`0x0208` | tunnel keepalive |
| TUNNELING_REQUEST | `0x0420` | one per scanned address (scan probe) |
| TUNNELING_ACK | `0x0421` | per-request acknowledgement |

Scan probe (`flow:to_server`, TCP/3671), byte offsets from the start of the
KNXnet/IP frame:

```text
06 10 04 20              KNXnet/IP header, service TUNNELING_REQUEST
04 <chan> <seq> 00       tunneling header (4 bytes), then cEMI:
11 00 B0 60              offset 10: cEMI L_Data.req (0x11), flags 0xB060
60 11 01 11 <NN>         cEMI body: control 0x60, src 1.1.1, dst 1.1.<NN> (swept)
00 80                    offset 18: APCI 0x0080 A_DeviceDescriptor_Read
```

## Rules

| SID | Match | Priority | Alerts on reference capture |
| --- | --- | --- | --- |
| `9999960` | CONNECT_REQUEST `06 10 02 05` on TCP/3671; sets `xbits knx_tcp_connect` | 3 | 2 |
| `9999961` | scan probe: TUNNELING_REQUEST + cEMI `11 00 B0 60` + APCI `00 80`; sets `xbits knx_scan_probe` | 3 | 522 |
| `9999962` | same probe with `threshold`: >= 20 probes in 600 s from one source | 2 | 3 |
| `9999963` | SEARCH_REQUEST `06 10 02 01` to 224.0.23.12:3671 (UDP multicast); sets `xbits knx_search` | 3 | not in the `lo` capture |
| `9999964` | DESCRIPTION_REQUEST `06 10 02 03` on TCP/3671 | 3 | 0 (this capture used UDP) |
| `9999965` | DESCRIPTION_REQUEST on UDP/3671 | 3 | 2 |
| `9999969` | correlation: `knx_tcp_connect` AND `knx_scan_probe` on the same IP pair, limited to 1 alert / 60 s | 1 | 4 |

Validation (Suricata 7.0.10, offline replay of the reference capture):

```bash
suricata -r knx/gateway-scan/oida_knx_gateway_scan.pcapng \
  -S knx/gateway-scan/oida_knx_gateway_scan.rules \
  -l /tmp/suri-knx --runmode single -k none
grep -o '999996.' /tmp/suri-knx/eve.json | sort | uniq -c
```

Observed: `9999960` x2, `9999961` x522, `9999962` x3, `9999965` x2,
`9999969` x4. Counts are high because a `lo` capture contains both directions
of every packet. The 600 s threshold window on `9999962` matches the real scan
duration (255 addresses with per-address timeouts span more than 60 s).

## False positives

- Engineering tools (ETS) also send SEARCH_REQUEST and DESCRIPTION_REQUEST;
  the multicast/description atomic rules alone are weak signals.
- The fingerprint value is the **combination**: a TCP tunnel plus hundreds of
  DeviceDescriptorRead probes to swept addresses (9999962) and the correlated
  alert 9999969. A single read by an HMI does not reach the threshold.
- `9999963` only fires if the capture includes a real interface
  (`tcpdump -i <iface>`, not `-i lo`): the multicast leaves on the external
  interface.

## ATT&CK for ICS mapping

[`attack_navigator_layer.json`](attack_navigator_layer.json) is a ready-to-import
MITRE ATT&CK Navigator layer (ICS matrix):

| Technique | Why |
| --- | --- |
| T0840 Network Connection Enumeration | tunnel + bus sweep maps device communication patterns |
| T0846 Remote System Discovery | 255-address DeviceDescriptorRead sweep |
| T0846.003 Multicast Discovery | SEARCH_REQUEST to 224.0.23.12:3671 |
| T0888 Remote System Information Discovery | DESCRIPTION_REQUEST (name, MAC, serial, services) |

## Lab notes (failed attempts kept as proof of work)

- UDP tunneling to 127.0.0.1 is rejected by the target ("retry with --tcp");
  `--tcp` works.
- `xknx` must be installed first (`pip install "oida-ics[knx]"`), otherwise
  OIDA aborts with "xknx library required".
- A first capture on `any` (LINUX_SLL2, linktype 276) cannot be replayed by
  Suricata 7 offline ("datalink type 276 not supported"); recaptured on
  `-i lo` (EN10MB).
- An early capture file was overwritten by failed attempts and contained only
  5 UDP packets; it was removed from the repository.
```
