"""
CNT 4713 Project 2 — DNS iterative client (single-file submission).

Run: python mydns.py <domain-name> <root-dns-ipv4>

"""

from __future__ import annotations

import socket
import sys
from typing import Iterable
import struct


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
    """
    import random

    if not domain_name:
        raise ValueError("domain_name must be non-empty")

    # Accept input
    name = domain_name.rstrip(".")
    if not name:
        raise ValueError("domain_name must contain at least one label")

    labels = name.split(".")
    for label in labels:
        if not label:
            raise ValueError("domain_name contains an empty label")
        if len(label) > 63:
            raise ValueError("each DNS label must be at most 63 bytes")
        try:
            label.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("domain_name must contain ASCII labels only") from exc

    # Transaction ID: random 16-bit value
    txid = random.getrandbits(16)

    # QR=0, Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
    flags = 0x0100

    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack("!HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)

    # QNAME: terminated by zero byte.
    qname_parts = []
    for label in labels:
        label_bytes = label.encode("ascii")
        qname_parts.append(struct.pack("!B", len(label_bytes)))
        qname_parts.append(label_bytes)
    qname_parts.append(b"\x00")
    qname = b"".join(qname_parts)

    # QTYPE=A (1), QCLASS=IN (1)
    question = qname + struct.pack("!HH", 1, 1)

    return header + question


# =============================================================================
# TEAM MEMBER 3 — Parse DNS replies (RFC 1035), appendix-style output
# Rubric: display reply; extract next NS IP; display final A answers
# =============================================================================

def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """
    Parse a DNS name starting at `offset` in `data`.
    Returns (name_string, offset_after_name).
    Handles RFC 1035 §4.1.4 compression pointers.
    """
    labels = []
    jumped = False
    end_offset = offset
    while True:
        length = data[offset]
        if length == 0:
            if not jumped:
                end_offset = offset + 1
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            if not jumped:
                end_offset = offset + 2  # caller resumes right after the 2-byte pointer
                jumped = True
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset = pointer
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode('ascii'))
            offset += length
    return '.'.join(labels), end_offset

def _parse_rr(data: bytes, offset: int) -> tuple[str, int, int, int, bytes, int]:
    """
    Parse one DNS Resource Record starting at `offset`.
    Returns (name, rtype, rclass, ttl, rdata_bytes, new_offset).
    """
    name, offset = _read_name(data, offset)

    rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset + 10])
    offset += 10

    rdata = data[offset:offset + rdlength]
    offset += rdlength

    return name, rtype, rclass, ttl, rdata, offset

def _parse_reply(data: bytes) -> dict:
    """
    Parse a full DNS reply into a dict with keys:
      'ancount', 'nscount', 'arcount',
      'answers', 'authority', 'additional'
    Each section is a list of dicts with keys:
      'name', 'rtype', 'rdata'
    """
    # --- Header ---
    _id, _flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', data[:12])
    offset = 12

    # --- Skip Question Section ---
    # Each question: QNAME (variable) + QTYPE (2B) + QCLASS (2B)
    for _ in range(qdcount):
        _, offset = _read_name(data, offset)
        offset += 4  # skip QTYPE + QCLASS

    # --- Parse helper: loop N times, collect RR dicts ---
    def parse_section(count):
        nonlocal offset
        records = []
        for _ in range(count):
            name, rtype, _rclass, _ttl, rdata, offset = _parse_rr(data, offset)
            rec = {'name': name, 'rtype': rtype}
            if rtype == 1:   # A record → decode IP immediately
                rec['ip'] = socket.inet_ntoa(rdata)
            elif rtype == 2: # NS record → rdata is a compressed name; decode it now
                ns_name, _ = _read_name(data, offset - len(rdata))
                rec['ns_name'] = ns_name
            records.append(rec)
        return records

    answers    = parse_section(ancount)
    authority  = parse_section(nscount)
    additional = parse_section(arcount)

    return {
        'ancount': ancount,
        'nscount': nscount,
        'arcount': arcount,
        'answers': answers,
        'authority': authority,
        'additional': additional,
    }

def format_reply_overview(reply: bytes) -> str:
    parsed = _parse_reply(reply)
    lines = []
    # Counts
    lines.append(f"{parsed['ancount']} Answers.")
    lines.append(f"{parsed['nscount']} Intermediate Name Servers.")
    lines.append(f"{parsed['arcount']} Additional Information Records.")
    # Answers section
    lines.append("Answers section:")
    for r in parsed['answers']:
        if r['rtype'] == 1:
            lines.append(f"Name : {r['name']} IP: {r['ip']}")
    # Authority section
    lines.append("Authority Section:")
    for r in parsed['authority']:
        if r['rtype'] == 2:
            lines.append(f"Name : {r['name']} Name Server: {r['ns_name']}")
    # Additional section
    lines.append("Additional Information Section:")
    for r in parsed['additional']:
        if r['rtype'] == 1:
            lines.append(f"Name : {r['name']} IP : {r['ip']}")
    return '\n'.join(lines)


def has_authoritative_a_answers(reply: bytes, domain_name: str) -> bool:
    parsed = _parse_reply(reply)
    return any(r['rtype'] == 1 for r in parsed['answers'])


def iter_answer_ipv4s(reply: bytes, domain_name: str) -> Iterable[str]:
    parsed = _parse_reply(reply)
    for r in parsed['answers']:
        if r['rtype'] == 1:
            yield r['ip']


def choose_next_nameserver_ip(reply: bytes) -> str | None:
    parsed = _parse_reply(reply)
    # Collect all NS names from Authority section
    ns_names = [r['ns_name'] for r in parsed['authority'] if r['rtype'] == 2]
    # Build a lookup: nameserver hostname → IP from Additional section
    glue = {r['name']: r['ip'] for r in parsed['additional'] if r['rtype'] == 1}
    # Find the first NS that has a glue record
    for ns_name in ns_names:
        if ns_name in glue:
            return glue[ns_name]
    return None  # No glue found — caller must handle this

# =============================================================================
# Integration — argument parsing + iterative resolution loop
# =============================================================================

_MAX_RESOLUTION_STEPS = 64


def usage() -> None:
    prog = "python mydns.py"
    print(f"Usage: {prog} <domain-name> <root-dns-ip>", file=sys.stderr)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        usage()
        return 1

    domain_name = argv[1].rstrip(".").lower()
    server_ip = argv[2]

    for _ in range(_MAX_RESOLUTION_STEPS):
        print("----------------------------------------------------------------")
        print(f"DNS server to query: {server_ip}")

        query_bytes = build_a_query(domain_name)
        reply_bytes = send_recv_dns(server_ip, query_bytes)

        print("Reply received. Content overview:")
        print(format_reply_overview(reply_bytes))

        if has_authoritative_a_answers(reply_bytes, domain_name):
            print("----------------------------------------------------------------")
            return 0

        next_ip = choose_next_nameserver_ip(reply_bytes)
        if next_ip is None:
            print(
                "Error: could not determine next nameserver IPv4 "
                "(check NS records and glue A records in Additional section).",
                file=sys.stderr,
            )
            return 2

        server_ip = next_ip

    print("Error: resolution exceeded maximum steps (possible loop).", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
