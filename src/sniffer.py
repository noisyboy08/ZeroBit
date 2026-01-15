"""
Packet sniffer entry point for ZeroBit.
Requires elevated privileges to capture packets.
"""

from __future__ import annotations

import argparse

from scapy.all import IP, sniff  # type: ignore


def handle_packet(pkt) -> None:
    """Callback for each captured packet."""
    try:
        if IP not in pkt:
            return
        ip_layer = pkt[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto
        size = len(pkt)
        print(f"[ZeroBit] src={src} dst={dst} proto={proto} size={size} bytes")
    except Exception as exc:  # pragma: no cover - runtime safety
        print(f"[ZeroBit] Packet parse failed: {exc}")


def run_sniffer(iface: str | None, count: int | None) -> None:
    sniff(iface=iface, prn=handle_packet, store=False, count=count)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ZeroBit packet sniffer.")
    parser.add_argument("--iface", type=str, default=None, help="Network interface to sniff on.")
    parser.add_argument("--count", type=int, default=None, help="Number of packets to capture.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_sniffer(args.iface, args.count)


if __name__ == "__main__":
    main()
