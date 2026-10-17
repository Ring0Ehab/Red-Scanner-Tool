#!/usr/bin/env python3
import sys
import argparse
import json
import socket
from collections import Counter
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# The default scanner uses only Python's standard library.

def banner():
    print(r"""
    ██████╗ ███████╗██████╗     ███████╗ ██████╗██████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
    ██╔══██╗██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
    ██████╔╝█████╗  ██║  ██║    ███████╗██║     ██████╔╝██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
    ██╔══██╗██╔══╝  ██║  ██║    ╚════██║██║     ██╔══██╗██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
    ██║  ██║███████╗██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
    ╚═╝  ╚═╝╚══════╝╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    """)

def service_name(port):
    # Convert a well-known port number such as 80 into a service name.
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"

def connect_scan_port(target_ip, port, show_filtered=False):
    # A connect scan asks the operating system to open a normal TCP connection.
    try:
        with socket.create_connection((target_ip, port), timeout=1.0):
            service = service_name(port)
            print(f"[+] Port {port} is OPEN (Service: {service})")
            return {"port": port, "state": "OPEN", "service": service}
    except (TimeoutError, socket.timeout):
        if show_filtered:
            print(f"[?] Port {port} is FILTERED (No response before timeout)")
        return {"port": port, "state": "FILTERED", "service": "unknown"}
    except ConnectionRefusedError:
        print(f"[-] Port {port} is CLOSED")
        return {"port": port, "state": "CLOSED", "service": "unknown"}
    except OSError:
        return {"port": port, "state": "UNKNOWN", "service": "unknown"}

def stealth_scan_port(target_ip, port, show_filtered=False):
    # SYN mode is optional and requires Scapy, Npcap on Windows, and elevated privileges.
    from scapy.all import IP, TCP, sr1, send, conf

    conf.verb = 0
    try:
        # A SYN packet starts a TCP handshake without completing the connection.
        syn_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=1.0, verbose=0)
        
        if response is None:
            if show_filtered:
                print(f"[?] Port {port} is FILTERED (No response)")
            return {"port": port, "state": "FILTERED", "service": "unknown"}
        elif response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)
            if tcp_layer.flags & 0x12 == 0x12:
                # SYN+ACK means the target accepted the connection attempt.
                rst_packet = IP(dst=target_ip) / TCP(dport=port, flags="R")
                send(rst_packet, verbose=0)
                
                service = service_name(port)
                    
                print(f"[+] Port {port} is OPEN (Service: {service})")
                return {"port": port, "state": "OPEN", "service": service}
            elif tcp_layer.flags & 0x14 == 0x14:
                # RST+ACK means the target rejected the connection attempt.
                print(f"[-] Port {port} is CLOSED")
                return {"port": port, "state": "CLOSED", "service": "unknown"}
    except (OSError, RuntimeError) as exc:
        print(f"[-] Could not scan port {port}: {type(exc).__name__}: {exc}")
    except Exception as exc:
        print(f"[-] Unexpected error scanning port {port}: {type(exc).__name__}: {exc}")
    return None

def packet_summary(packet):
    """Return metadata only; packet payloads are intentionally not collected."""
    from scapy.all import IP, IPv6, TCP, UDP, ICMP

    ip_layer = packet.getlayer(IP)
    if ip_layer is None:
        ip_layer = packet.getlayer(IPv6)
    if ip_layer is None:
        return None

    protocol = "OTHER"
    source_port = None
    destination_port = None
    if packet.haslayer(TCP):
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    return {
        "source": ip_layer.src,
        "destination": ip_layer.dst,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "length": len(packet),
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }

def passive_sniff(
    interface=None,
    duration=30,
    packet_count=0,
    bpf_filter=None,
    show_packets=False,
):
    """Capture packet metadata on an authorized interface without modifying traffic."""
    try:
        from scapy.all import sniff
    except ImportError:
        print("[-] Sniff mode requires Scapy. Install it with: python -m pip install -r requirements-syn.txt")
        sys.exit(1)

    summaries = []

    def collect(packet):
        summary = packet_summary(packet)
        if summary:
            summaries.append(summary)
            if show_packets:
                source = summary["source"]
                destination = summary["destination"]
                protocol = summary["protocol"]
                source_port = summary["source_port"]
                destination_port = summary["destination_port"]
                ports = ""
                if source_port is not None and destination_port is not None:
                    ports = f":{source_port} -> :{destination_port}"
                print(f"[PACKET] {source}{ports} -> {destination} {protocol}")

    print("[*] Passive capture started; packet payloads are not stored.")
    try:
        sniff(
            iface=interface or None,
            filter=bpf_filter or None,
            prn=collect,
            store=False,
            timeout=duration if packet_count == 0 else None,
            count=packet_count,
        )
    except (OSError, RuntimeError) as exc:
        print(f"[-] Could not capture packets: {type(exc).__name__}: {exc}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Capture interrupted by user.")

    protocol_counts = Counter(item["protocol"] for item in summaries)
    print(f"[*] Passive capture completed: {len(summaries)} IP packets")
    for protocol, count in sorted(protocol_counts.items()):
        print(f"    {protocol}: {count}")
    return summaries

def main():
    # argparse creates the command-line interface shown by --help.
    parser = argparse.ArgumentParser(
        description="Authorized TCP port scanner and passive network observer",
        epilog="Use only on systems and networks you own or are explicitly authorized to test.",
    )
    parser.add_argument("-t", "--target", help="Target IP address or hostname (required for scanning)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g., 1-1000)")
    parser.add_argument("-c", "--threads", type=int, default=50, help="Number of concurrent threads")
    parser.add_argument("-o", "--output", help="Save results to a JSON file")
    parser.add_argument(
        "--show-filtered",
        action="store_true",
        help="Show filtered ports in the terminal (hidden by default)",
    )
    parser.add_argument(
        "--scan-type",
        choices=("connect", "syn"),
        default="connect",
        help="connect works without extra dependencies; syn requires Scapy and raw-packet privileges",
    )
    parser.add_argument(
        "--sniff",
        action="store_true",
        help="Passively capture packet metadata for 30 seconds; does not alter traffic",
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Interface for passive capture (default: Scapy's default interface)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Passive capture duration in seconds (default: 30)",
    )
    parser.add_argument(
        "--packet-count",
        type=int,
        default=0,
        help="Stop passive capture after this many packets (0 uses --duration)",
    )
    parser.add_argument(
        "--bpf-filter",
        help="Optional BPF filter for passive capture, for example 'tcp or udp'",
    )
    parser.add_argument(
        "--show-packets",
        action="store_true",
        help="Print one metadata-only line for each captured IP packet",
    )
    
    args = parser.parse_args()
    # Windows consoles may use an encoding that cannot print the banner.
    output_stream = getattr(sys.stdout, "stream", sys.stdout)
    if hasattr(output_stream, "reconfigure"):
        output_stream.reconfigure(encoding="utf-8", errors="replace")
    banner()
    
    if args.sniff:
        if args.target:
            parser.error("--target cannot be used with --sniff")
        if args.duration < 1:
            print("[-] Error: Duration must be greater than zero.")
            sys.exit(1)
        if args.packet_count < 0:
            print("[-] Error: Packet count cannot be negative.")
            sys.exit(1)
        summaries = passive_sniff(
            interface=args.interface,
            duration=args.duration,
            packet_count=args.packet_count,
            bpf_filter=args.bpf_filter,
            show_packets=args.show_packets,
        )
        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as json_file:
                    json.dump(
                        {
                            "capture_time_seconds": args.duration,
                            "timestamp": str(datetime.now()),
                            "interface": args.interface or "default",
                            "filter": args.bpf_filter,
                            "packets": summaries,
                        },
                        json_file,
                        indent=4,
                    )
                print(f"[+] Capture metadata exported to {args.output}")
            except OSError as exc:
                print(f"[-] Error saving file: {exc}")
                sys.exit(1)
        return

    if not args.target:
        parser.error("--target is required unless --sniff is used")

    try:
        # Resolve a hostname once, then reuse its IP for every port.
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[-] Error: Could not resolve hostname {args.target}")
        sys.exit(1)
        
    try:
        # Accept either one port ("80") or an inclusive range ("1-1000").
        if "-" in args.ports:
            parts = args.ports.split("-")
            if len(parts) != 2:
                raise ValueError
            start_port, end_port = map(int, parts)
        else:
            start_port = end_port = int(args.ports)
    except ValueError:
        print("[-] Error: Invalid port range format.")
        sys.exit(1)

    if not (1 <= start_port <= end_port <= 65535):
        print("[-] Error: Ports must be between 1 and 65535, with the start no greater than the end.")
        sys.exit(1)
    if args.threads < 1:
        print("[-] Error: Threads must be greater than zero.")
        sys.exit(1)

    if args.scan_type == "syn":
        # Import Scapy only when requested, so connect mode stays dependency-free.
        try:
            import scapy.all  # noqa: F401
        except ImportError:
            print("[-] SYN mode requires Scapy. Install it with: python -m pip install -r requirements-syn.txt")
            sys.exit(1)

    print(f"[*] Target IP    : {target_ip}")
    print(f"[*] Port Range   : {start_port} to {end_port}")
    print(f"[*] Scan Type    : TCP {args.scan_type}")
    print(f"[*] Threads      : {args.threads}")
    print("-" * 60)

    t1 = datetime.now()
    open_ports = []
    scan_results = []

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            # Scan several ports concurrently to reduce the total waiting time.
            scan_function = connect_scan_port if args.scan_type == "connect" else stealth_scan_port
            futures = {
                executor.submit(scan_function, target_ip, port, args.show_filtered): port
                for port in range(start_port, end_port + 1)
            }
            for future in futures:
                res = future.result()
                if res:
                    scan_results.append(res)
                    if res["state"] == "OPEN":
                        open_ports.append(res)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)

    t2 = datetime.now()
    total_time = t2 - t1
    
    print("-" * 60)
    print(f"[*] Scan completed in: {total_time}")
    print(f"[*] Total Open Ports Found: {len(open_ports)}")
    closed_count = sum(result["state"] == "CLOSED" for result in scan_results)
    filtered_count = sum(result["state"] == "FILTERED" for result in scan_results)
    if args.show_filtered:
        print(f"[*] Closed: {closed_count} | Filtered: {filtered_count}")
    else:
        print(f"[*] Closed: {closed_count}")

    if args.output:
        # JSON output makes the scan results easy to store or process elsewhere.
        report_data = {
            "target": target_ip,
            "scan_time": str(total_time),
            "timestamp": str(datetime.now()),
            "open_ports": open_ports,
            "scan_results": scan_results
        }
        try:
            with open(args.output, "w", encoding="utf-8") as json_file:
                json.dump(report_data, json_file, indent=4)
            print(f"[+] Results successfully exported to {args.output}")
        except Exception as e:
            print(f"[-] Error saving file: {e}")

if __name__ == "__main__":
    main()