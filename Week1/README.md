# Port Scanner and Passive Network Observer

This project contains two deliberately separate, authorized workflows:

```text
                 ┌─────────────────────────────┐
                 │         port_scanner.py      │
                 └──────────────┬──────────────┘
                                │
              ┌─────────────────┴─────────────────┐
              │                                   │
   ┌──────────▼──────────┐             ┌──────────▼──────────┐
   │ TCP connect / SYN    │             │ Passive --sniff      │
   │ port discovery       │             │ metadata observation  │
   └──────────┬──────────┘             └──────────┬──────────┘
              │                                   │
       target + ports                    interface + filter
              │                                   │
       JSON scan report                  JSON metadata report
```

The passive mode does **not** perform ARP spoofing, traffic interception,
packet injection, credential collection, routing changes, or traffic
manipulation. Turning a machine into a gateway or impersonating another host
is an active attack and is outside this tool's scope. Use a dedicated,
isolated lab and purpose-built defensive tools for authorized training.

The default scanner uses Python's standard library, so it does not require
Scapy, Npcap, Docker, or administrator privileges in most environments.

## Quick start

```bash
python port_scanner.py -t TARGET -p 1-1000
```

Only scan systems that you own or have explicit permission to test. A safe
local test target is `127.0.0.1`, especially when you start a local service:

```bash
python -m http.server 8765 --bind 127.0.0.1
python port_scanner.py -t 127.0.0.1 -p 8765
```

See every available option:

```bash
python port_scanner.py --help
```

## Passive network observation

`--sniff` captures packet metadata only. It does not save packet payloads and
stops after 30 seconds by default:

```bash
python port_scanner.py --sniff
python port_scanner.py --sniff --interface "Ethernet" --duration 60
python port_scanner.py --sniff --packet-count 100 --bpf-filter "tcp or udp" -o capture.json
python port_scanner.py --sniff --duration 30 --show-packets
```

Scapy is required for this mode. On Windows, Npcap and an elevated terminal
may be required. On Linux, packet-capture permissions may be required. Select
only an interface and traffic that you are authorized to monitor.

`--show-packets` prints source, destination, protocol, and ports only. Packet
payloads are never printed or written to the JSON report.

## Optional SYN mode

SYN mode is not required for the normal workflow. It requires Scapy and
raw-packet privileges:

```bash
python -m pip install -r requirements-syn.txt
python port_scanner.py -t TARGET -p 1-1000 --scan-type syn
```

On Windows, SYN mode may also require Npcap and an elevated terminal. On
Linux, the process or container needs the appropriate raw-network capability.

## Docker

Docker is optional for the default scanner:

```bash
docker build -t port-scanner .
docker run --rm port-scanner -t TARGET -p 1-1000
```

Docker networking and raw-packet permissions must be configured separately
when using SYN mode. Docker does not install itself or change host firewall
and network permissions.

## Port states

The scanner reports:

- `OPEN`: the target accepted the TCP connection.
- `CLOSED`: the target rejected the connection.
- `FILTERED`: no response arrived before the timeout, which can indicate a
  firewall or packet filter. It is not proof that the port is open or closed.

Filtered ports are hidden from the terminal by default so that open and closed
ports are easier to see. Show them explicitly when needed:

```bash
python port_scanner.py -t TARGET -p 1-1000 --show-filtered
```
