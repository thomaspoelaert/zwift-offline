#!/usr/bin/env python

"""
Zwift Video Network Capture Tool

Captures DNS queries and HTTP/HTTPS requests from Zwift to identify
which domains serve video content (Zwift Video / Zwift Plus).

Usage:
    python zwift_video_capture.py [--interface eth0] [--duration 300]

Run this BEFORE enabling the video cache proxy, while using Zwift Video
on a real route. The script will log all Zwift-related domains and
traffic patterns so you can configure the cache accordingly.

Requirements:
    pip install scapy (for DNS capture)
    Or run with --dns-only to use a simpler socket-based capture.
"""

import argparse
import json
import os
import re
import socket
import struct
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime

KNOWN_ZWIFT_DOMAINS = [
    'zwift.com',
    'cdn.zwift.com',
    'secure.zwift.com',
    'us-or-rly101.zwift.com',
    'launcher.zwift.com',
]

VIDEO_INDICATORS = [
    '.m3u8',    # HLS manifest
    '.ts',      # HLS segment (MPEG-TS)
    '.m4s',     # DASH segment
    '.mpd',     # DASH manifest
    '.mp4',     # Progressive video
    '.fmp4',    # Fragmented MP4
    '/video',
    '/stream',
    '/hls/',
    '/dash/',
    '/manifest',
    'akamai',
    'cloudfront',
    'fastly',
    'edgecast',
    'limelight',
    'rouvy',
]

class DomainTracker:
    def __init__(self):
        self.domains = defaultdict(lambda: {
            'first_seen': None,
            'last_seen': None,
            'query_count': 0,
            'resolved_ips': set(),
            'is_video_candidate': False,
            'notes': [],
        })
        self.lock = threading.Lock()

    def add_domain(self, domain, ip=None, note=None):
        with self.lock:
            entry = self.domains[domain]
            now = datetime.now().isoformat()
            if not entry['first_seen']:
                entry['first_seen'] = now
            entry['last_seen'] = now
            entry['query_count'] += 1
            if ip:
                entry['resolved_ips'].add(ip)
            if note:
                entry['notes'].append(note)
            for indicator in VIDEO_INDICATORS:
                if indicator in domain.lower():
                    entry['is_video_candidate'] = True

    def get_report(self):
        with self.lock:
            report = {
                'capture_time': datetime.now().isoformat(),
                'known_zwift_domains': [],
                'new_domains': [],
                'video_candidates': [],
            }
            for domain, info in sorted(self.domains.items()):
                entry = {
                    'domain': domain,
                    'query_count': info['query_count'],
                    'first_seen': info['first_seen'],
                    'last_seen': info['last_seen'],
                    'resolved_ips': list(info['resolved_ips']),
                    'notes': info['notes'],
                }
                if any(known in domain for known in KNOWN_ZWIFT_DOMAINS):
                    report['known_zwift_domains'].append(entry)
                elif info['is_video_candidate']:
                    report['video_candidates'].append(entry)
                else:
                    report['new_domains'].append(entry)
            return report


class DNSCaptureServer:
    """Passive DNS capture using a DNS server that logs and forwards queries."""

    def __init__(self, tracker, listen_port=5353, upstream='8.8.8.8'):
        self.tracker = tracker
        self.listen_port = listen_port
        self.upstream = upstream
        self.running = False

    def start(self):
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', self.listen_port))
        self.sock.settimeout(1.0)
        print(f"[DNS Capture] Listening on port {self.listen_port}")
        print(f"[DNS Capture] Forwarding to {self.upstream}")

        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                domain = self._parse_dns_query(data)
                if domain:
                    ip = self._forward_and_resolve(data, domain)
                    self.tracker.add_domain(domain, ip, f"DNS query from {addr[0]}")
                    self._send_response(data, addr, ip)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[DNS Capture] Error: {e}")

    def _parse_dns_query(self, data):
        try:
            # Skip header (12 bytes), parse question section
            pos = 12
            labels = []
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    break
                pos += 1
                labels.append(data[pos:pos+length].decode('ascii', errors='ignore'))
                pos += length
            return '.'.join(labels) if labels else None
        except Exception:
            return None

    def _forward_and_resolve(self, query_data, domain):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(query_data, (self.upstream, 53))
            response, _ = sock.recvfrom(4096)
            sock.close()
            # Parse first A record from response
            return self._parse_dns_response_ip(response)
        except Exception:
            return None

    def _parse_dns_response_ip(self, data):
        try:
            # Skip header
            qdcount = struct.unpack('!H', data[4:6])[0]
            ancount = struct.unpack('!H', data[6:8])[0]
            pos = 12
            # Skip questions
            for _ in range(qdcount):
                while data[pos] != 0:
                    if data[pos] >= 0xC0:
                        pos += 2
                        break
                    pos += data[pos] + 1
                else:
                    pos += 1
                pos += 4  # QTYPE + QCLASS
            # Read first answer
            for _ in range(ancount):
                if data[pos] >= 0xC0:
                    pos += 2
                else:
                    while data[pos] != 0:
                        pos += data[pos] + 1
                    pos += 1
                rtype = struct.unpack('!H', data[pos:pos+2])[0]
                pos += 8  # TYPE + CLASS + TTL
                rdlength = struct.unpack('!H', data[pos:pos+2])[0]
                pos += 2
                if rtype == 1 and rdlength == 4:  # A record
                    return socket.inet_ntoa(data[pos:pos+4])
                pos += rdlength
        except Exception:
            pass
        return None

    def _send_response(self, original_query, addr, resolved_ip):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(original_query, (self.upstream, 53))
            response, _ = sock.recvfrom(4096)
            sock.close()
            self.sock.sendto(response, addr)
        except Exception:
            pass

    def stop(self):
        self.running = False
        self.sock.close()


class TrafficLogger:
    """Log HTTP(S) traffic patterns from Zwift by monitoring connections."""

    def __init__(self, tracker):
        self.tracker = tracker
        self.connections = defaultdict(lambda: {
            'bytes_sent': 0,
            'bytes_received': 0,
            'connection_count': 0,
            'first_seen': None,
            'last_seen': None,
        })
        self.lock = threading.Lock()

    def log_connection(self, remote_ip, remote_port, bytes_transferred=0):
        with self.lock:
            key = f"{remote_ip}:{remote_port}"
            conn = self.connections[key]
            now = datetime.now().isoformat()
            if not conn['first_seen']:
                conn['first_seen'] = now
            conn['last_seen'] = now
            conn['connection_count'] += 1
            conn['bytes_received'] += bytes_transferred

    def get_high_bandwidth(self, threshold_bytes=10_000_000):
        with self.lock:
            return {
                k: v for k, v in self.connections.items()
                if v['bytes_received'] > threshold_bytes
            }


def capture_with_netstat(tracker, duration, interval=5):
    """Monitor network connections using netstat/ss to identify high-traffic hosts."""
    print(f"[Traffic Monitor] Monitoring connections for {duration}s (interval: {interval}s)")
    print("[Traffic Monitor] Start a Zwift Video ride now!")
    logger = TrafficLogger(tracker)
    start = time.time()

    while time.time() - start < duration:
        try:
            import subprocess
            result = subprocess.run(
                ['ss', '-tnp', 'state', 'established'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if 'zwift' in line.lower() or ':443' in line or ':80' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        recv_bytes = 0
                        remote = parts[4] if len(parts) > 4 else ''
                        if ':' in remote:
                            ip, port = remote.rsplit(':', 1)
                            logger.log_connection(ip, port, recv_bytes)
                            try:
                                hostname = socket.gethostbyaddr(ip)[0]
                                tracker.add_domain(hostname, ip, "Reverse DNS from active connection")
                            except (socket.herror, socket.gaierror):
                                tracker.add_domain(ip, ip, "Active connection (no reverse DNS)")
        except Exception as e:
            print(f"[Traffic Monitor] Error: {e}")
        time.sleep(interval)

    high_bw = logger.get_high_bandwidth()
    if high_bw:
        print("\n[Traffic Monitor] High-bandwidth connections (>10MB):")
        for addr, info in sorted(high_bw.items(), key=lambda x: x[1]['bytes_received'], reverse=True):
            print(f"  {addr}: {info['connection_count']} connections, "
                  f"~{info['bytes_received']/1024/1024:.1f} MB received")


def save_report(tracker, output_file):
    report = tracker.get_report()
    # Convert sets to lists for JSON
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[Report] Saved to {output_file}")

    print("\n=== CAPTURE REPORT ===\n")

    if report['video_candidates']:
        print("VIDEO CANDIDATE DOMAINS (likely serving Zwift Video):")
        for d in report['video_candidates']:
            print(f"  * {d['domain']}")
            if d['resolved_ips']:
                print(f"    IPs: {', '.join(d['resolved_ips'])}")
            print(f"    Queries: {d['query_count']}")
    else:
        print("No video candidate domains detected.")
        print("Tip: Make sure you started a Zwift Video route during capture.")

    if report['new_domains']:
        print(f"\nOTHER NEW DOMAINS ({len(report['new_domains'])}):")
        for d in report['new_domains']:
            print(f"  - {d['domain']} (queries: {d['query_count']})")

    print("\nKNOWN ZWIFT DOMAINS:")
    for d in report['known_zwift_domains']:
        print(f"  - {d['domain']} (queries: {d['query_count']})")

    print("\n=== NEXT STEPS ===")
    print("1. Add video domains to storage/video_cache_domains.txt (one per line)")
    print("2. Enable the video cache: create storage/video-cache.txt")
    print("3. Restart zwift-offline")
    print("4. Ride the same video route again — it will be cached locally")


def main():
    parser = argparse.ArgumentParser(description='Zwift Video Network Capture Tool')
    parser.add_argument('--duration', type=int, default=300,
                        help='Capture duration in seconds (default: 300)')
    parser.add_argument('--output', default='storage/video_capture_report.json',
                        help='Output report file path')
    parser.add_argument('--dns-port', type=int, default=5353,
                        help='DNS capture port (default: 5353)')
    parser.add_argument('--monitor-only', action='store_true',
                        help='Only monitor connections, no DNS capture')
    args = parser.parse_args()

    tracker = DomainTracker()

    print("=" * 60)
    print("  Zwift Video Network Capture Tool")
    print("=" * 60)
    print()
    print(f"Duration: {args.duration}s")
    print(f"Output: {args.output}")
    print()
    print("Instructions:")
    print("1. Start Zwift and log in with your Zwift Plus account")
    print("2. Select a Zwift Video route")
    print("3. Start riding — the capture will identify video domains")
    print()

    threads = []

    if not args.monitor_only:
        dns_server = DNSCaptureServer(tracker, listen_port=args.dns_port)
        dns_thread = threading.Thread(target=dns_server.start, daemon=True)
        dns_thread.start()
        threads.append(('DNS', dns_thread, dns_server))

    monitor_thread = threading.Thread(
        target=capture_with_netstat,
        args=(tracker, args.duration),
        daemon=True
    )
    monitor_thread.start()

    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print("\n[Main] Capture interrupted by user")

    for name, thread, server in threads:
        if hasattr(server, 'stop'):
            server.stop()

    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
    save_report(tracker, args.output)


if __name__ == '__main__':
    main()
