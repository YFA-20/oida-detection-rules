# KNXnet/IP - OIDA capability map

OIDA's KNX engine (xknx) against KNXnet/IP on UDP/TCP 3671. This page maps the
`oida knx` command surface; the per-command detection notes live in the
fingerprint subfolders.

Reference version: OIDA 1.0.6 (install the xknx dependency with
`pip install "oida-ics[knx]"`). KNX has no encryption and no authentication
at the protocol level; OIDA prints both warnings on every run.

## Contents

| Path | Content |
| --- | --- |
| [`gateway-scan/`](gateway-scan/) | fingerprint for `oida knx <IP> -p 3671 --gateway-scan --tcp` |
| [`gateway-scan/README.md`](gateway-scan/README.md) | PDU sequence, rule table, validation |
| [`gateway-scan/oida_knx_gateway_scan.rules`](gateway-scan/oida_knx_gateway_scan.rules) | Suricata rules |
| [`gateway-scan/oida_knx_gateway_scan.pcapng`](gateway-scan/oida_knx_gateway_scan.pcapng) | reference capture, 3256 packets |

## Command surface

### Connection

| Option | Meaning | Default |
| --- | --- | --- |
| `-p/--port` | KNXnet/IP port | `3671` |
| `-t/--timeout` | connection timeout (s) | `5.0` |
| `--tcp` | TCP tunneling instead of UDP tunneling | UDP |
| `--no-nat` | disable NAT mode (explicit local IP in requests) | NAT on |
| `--interface` | bind discovery to a local interface or IPv4 | auto |

UDP tunneling is rejected by many IP routers and by loopback/NAT'd targets;
`--tcp` is the reliable mode there.

### Reconnaissance

| Option | Capability |
| --- | --- |
| `--gateway-scan` | discover KNX/IP gateways: multicast SEARCH_REQUEST, unicast DESCRIPTION_REQUEST, then device scan |
| `--bus-scan` | sweep bus devices and listen for traffic |
| `--listen` / `-L SECONDS` | passive monitor, no probes |
| `-r/--scan-range` | custom individual-address range (e.g. `1.1.1-1.1.255`) |
| `--serial-scan`, `--domain-serial` | locate a device by serial / domain address |
| `--slow-scan` | slow individual-address check |

### Device operations

| Option | Capability | Writes |
| --- | --- | --- |
| `--device-info` | descriptor, serial, manufacturer | no |
| `--firmware-info` | firmware and BCU information | no |
| `--enumerate-objects`, `--vendor-objects` | interface objects, vendor range 200-255 | no |
| `--prop-read`, `--prop-desc`, `--prop-dump` | interface object properties | no |
| `--memory-dump`, `--memory-ext`, `--memory-user` | read memory ranges | no |
| `--adc-read` | read ADC channel | no |
| `--memory-write`, `--property-write`, `--fuzz-property` | write memory / property | `--confirm` |
| `--group-write ADDR:VALUE` | write a group address | `--confirm` |
| `--restart`, `--master-reset MODE` | reboot / master reset a BCU | `-i`, `--confirm` |

### Authentication (BCU keys)

| Option | Capability | Writes |
| --- | --- | --- |
| `--auth-test [KEY]`, `--key-file`, `--key-range` | test BCU keys (default factory key `FFFFFFFF`) | probe |
| `--key-write KEY:LEVEL` | write a BCU key | DANGEROUS |

### Project files

| Option | Capability |
| --- | --- |
| `--knxproj FILE` with `--knxproj-password` / `--knxproj-wordlist` / `--knxproj-hash` | decrypt and parse ETS project files |

## Fingerprints

| Command | Subfolder | Detection |
| --- | --- | --- |
| `oida knx <IP> -p 3671 --gateway-scan --tcp` | [`gateway-scan/`](gateway-scan/) | CONNECT_REQUEST, DeviceDescriptorRead sweep, gateway DESCRIPTION_REQUEST, correlated by xbits |
