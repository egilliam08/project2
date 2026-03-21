#!/usr/bin/env python3
"""
CNT 4713 Project 2 — DNS iterative client (single-file submission).

Run: python mydns.py <domain-name> <root-dns-ipv4>

Workload (same module, marked sections below):
  • TEAM MEMBER 1 — UDP send/receive (send_recv_dns); integration (main loop) after 2 & 3
  • TEAM MEMBER 2 — Build query packets (build_a_query)
  • TEAM MEMBER 3 — Parse replies, formatting, next server, final A records

Everyone: RFC 1035 / textbook DNS; match assignment appendix output.
"""

from __future__ import annotations

import socket
import sys
from typing import Iterable


# =============================================================================
# TEAM MEMBER 1 — UDP socket layer (DNS uses UDP port 53)
# Rubric: send/receive queries to root and intermediate servers
# =============================================================================

DNS_PORT = 53
DEFAULT_TIMEOUT_SEC = 5.0
# DNS over UDP: responses are often ≤512 bytes without EDNS; allow room for larger replies.
_RECV_BUFSIZE = 4096


def send_recv_dns(server_ip: str, request_bytes: bytes, timeout_sec: float = DEFAULT_TIMEOUT_SEC) -> bytes:
    """
    Send a DNS query over UDP to server_ip:DNS_PORT and return the response datagram (payload only).
    """
    addr = (server_ip, DNS_PORT)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout_sec)
            sock.sendto(request_bytes, addr)
            data, _ = sock.recvfrom(_RECV_BUFSIZE)
    except socket.timeout:
        print(
            f"DNS error: no reply from {server_ip} port {DNS_PORT} within {timeout_sec} s.",
            file=sys.stderr,
        )
        raise
    except OSError as exc:
        print(
            f"DNS error: UDP send/recv to {server_ip} port {DNS_PORT} failed: {exc}",
            file=sys.stderr,
        )
        raise
    return data


# =============================================================================
# TEAM MEMBER 2 — Build DNS query messages (RFC 1035)
# Rubric: valid wire format for “send query …”
# =============================================================================


def build_a_query(domain_name: str) -> bytes:
    """
    Build a DNS query for type A, class IN, for the given domain (no trailing dot required).

    TODO (Member 2):
      - Choose transaction ID (e.g. random 16-bit).
      - Flags: standard query; recursion desired per course notes vs iterative client.
      - QDCOUNT=1; ANCOUNT=NSCOUNT=ARCOUNT=0.
      - Question section: QNAME + QTYPE=1 + QCLASS=1.
    """
    raise NotImplementedError("Team Member 2: implement build_a_query() per RFC 1035")


# =============================================================================
# TEAM MEMBER 3 — Parse DNS replies (RFC 1035), appendix-style output
# Rubric: display reply; extract next NS IP; display final A answers
# =============================================================================


def format_reply_overview(reply: bytes) -> str:
    """
    Return multi-line text: counts + Answers / Authority / Additional sections (appendix style).

    TODO (Member 3): parse reply and format like the sample output.
    """
    raise NotImplementedError("Team Member 3: implement format_reply_overview()")


def has_authoritative_a_answers(reply: bytes, domain_name: str) -> bool:
    """True if the Answer section contains A record(s) for domain_name (IPv4 terminal state)."""
    raise NotImplementedError("Team Member 3: implement has_authoritative_a_answers()")


def iter_answer_ipv4s(reply: bytes, domain_name: str) -> Iterable[str]:
    """Yield IPv4 dotted strings from A RRs in the Answer section for domain_name."""
    raise NotImplementedError("Team Member 3: implement iter_answer_ipv4s()")


def choose_next_nameserver_ip(reply: bytes) -> str | None:
    """
    Pick one NS from Authority, find glue A in Additional; return that IPv4 or None.

    TODO (Member 3):
      - If glue is missing for the chosen NS, a full resolver would resolve the NS name;
        the assignment often assumes glue is present — document any fallback you add.
    """
    raise NotImplementedError("Team Member 3: implement choose_next_nameserver_ip()")


# =============================================================================
# Integration — argument parsing + iterative resolution loop
# Owner: Team member 1 — implement AFTER Team members 2 & 3 finish their functions.
# =============================================================================


def usage() -> None:
    prog = "python mydns.py"
    print(f"Usage: {prog} <domain-name> <root-dns-ip>", file=sys.stderr)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        usage()
        return 1

    # --- Integration (TODO: uncomment / implement when build_a_query + parsers exist) ---

    print(
        "Integration not wired yet — implement main() after teammates finish "
        "build_a_query and the dns_parse helpers.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
