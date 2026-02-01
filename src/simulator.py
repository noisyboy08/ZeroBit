"""
Attack Simulator for testing ZeroBit's Adaptive Learning system.
Generates controlled attack traffic and safe traffic for model validation.
"""

from __future__ import annotations

import random
import time
from typing import List

from scapy.all import IP, TCP, UDP, DNS, DNSQR, send, RandShort  # type: ignore


class AttackSimulator:
    """Simulates various attack patterns and safe traffic for testing."""

    def __init__(self, source_ip: str = "192.168.1.100") -> None:
        self.source_ip = source_ip

    def simulate_dos(self, target_ip: str, duration: int = 5, packet_rate: int = 10) -> int:
        """
        Simulate a DoS attack by flooding target with TCP SYN packets.
        Returns number of packets sent.
        """
        print(f"[Simulator] Starting DoS attack on {target_ip} for {duration} seconds...")
        end_time = time.time() + duration
        packet_count = 0

        try:
            while time.time() < end_time:
                # Generate random source port
                src_port = RandShort()
                # Create TCP SYN packet
                packet = IP(src=self.source_ip, dst=target_ip) / TCP(
                    sport=src_port, dport=80, flags="S"
                )
                send(packet, verbose=False)
                packet_count += 1
                time.sleep(1.0 / packet_rate)  # Control packet rate
        except Exception as exc:
            print(f"[Simulator] DoS simulation error: {exc}")

        print(f"[Simulator] DoS attack complete. Sent {packet_count} packets.")
        return packet_count

    def simulate_probe(self, target_ip: str, num_ports: int = 20) -> int:
        """
        Simulate port scanning/probing by sending packets to random ports.
        Returns number of packets sent.
        """
        print(f"[Simulator] Starting port probe on {target_ip}...")
        packet_count = 0
        ports_to_scan = random.sample(range(1, 1025), min(num_ports, 1024))

        try:
            for port in ports_to_scan:
                # Random protocol choice (TCP or UDP)
                protocol = random.choice(["TCP", "UDP"])
                src_port = RandShort()

                if protocol == "TCP":
                    packet = IP(src=self.source_ip, dst=target_ip) / TCP(
                        sport=src_port, dport=port, flags="S"
                    )
                else:
                    packet = IP(src=self.source_ip, dst=target_ip) / UDP(
                        sport=src_port, dport=port
                    )

                send(packet, verbose=False)
                packet_count += 1
                time.sleep(0.1)  # Small delay between probes
        except Exception as exc:
            print(f"[Simulator] Probe simulation error: {exc}")

        print(f"[Simulator] Port probe complete. Scanned {packet_count} ports.")
        return packet_count

    def simulate_noise(self, target_ip: str = "8.8.8.8", num_packets: int = 10) -> int:
        """
        Generate safe, legitimate traffic (HTTP/DNS) to test for false positives.
        This should NOT trigger alerts after the model learns from feedback.
        Returns number of packets sent.
        """
        print(f"[Simulator] Generating safe traffic (HTTP/DNS) to {target_ip}...")
        packet_count = 0

        try:
            for _ in range(num_packets):
                # Random choice between HTTP-like and DNS-like traffic
                traffic_type = random.choice(["HTTP", "DNS"])

                if traffic_type == "HTTP":
                    # Simulate HTTP GET request (normal web browsing)
                    src_port = random.randint(49152, 65535)  # Ephemeral port range
                    packet = IP(src=self.source_ip, dst=target_ip) / TCP(
                        sport=src_port, dport=80, flags="PA"
                    )
                else:
                    # Simulate DNS query (normal DNS lookup)
                    src_port = random.randint(49152, 65535)
                    packet = (
                        IP(src=self.source_ip, dst=target_ip)
                        / UDP(sport=src_port, dport=53)
                        / DNS(rd=1, qd=DNSQR(qname="example.com"))
                    )

                send(packet, verbose=False)
                packet_count += 1
                time.sleep(0.5)  # Normal traffic has delays
        except Exception as exc:
            print(f"[Simulator] Safe traffic simulation error: {exc}")

        print(f"[Simulator] Safe traffic generation complete. Sent {packet_count} packets.")
        return packet_count

    def simulate_benign_http(self, target_ip: str, num_requests: int = 5) -> int:
        """
        Generate multiple benign HTTP requests to simulate normal browsing.
        """
        print(f"[Simulator] Generating {num_requests} benign HTTP requests...")
        packet_count = 0

        try:
            for i in range(num_requests):
                src_port = random.randint(49152, 65535)
                # Normal HTTP GET with ACK flag (established connection)
                packet = IP(src=self.source_ip, dst=target_ip) / TCP(
                    sport=src_port, dport=80, flags="PA", seq=1000 + i, ack=2000 + i
                )
                send(packet, verbose=False)
                packet_count += 1
                time.sleep(1.0)  # Normal browsing delay
        except Exception as exc:
            print(f"[Simulator] HTTP simulation error: {exc}")

        return packet_count

    def simulate_normal_dns(self, num_queries: int = 5) -> int:
        """
        Generate normal DNS queries (safe traffic).
        """
        print(f"[Simulator] Generating {num_queries} DNS queries...")
        packet_count = 0
        dns_servers = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
        domains = ["google.com", "github.com", "stackoverflow.com", "reddit.com", "wikipedia.org"]

        try:
            for _ in range(num_queries):
                dns_server = random.choice(dns_servers)
                domain = random.choice(domains)
                src_port = random.randint(49152, 65535)

                packet = (
                    IP(src=self.source_ip, dst=dns_server)
                    / UDP(sport=src_port, dport=53)
                    / DNS(rd=1, qd=DNSQR(qname=domain))
                )
                send(packet, verbose=False)
                packet_count += 1
                time.sleep(0.5)
        except Exception as exc:
            print(f"[Simulator] DNS simulation error: {exc}")

        return packet_count

