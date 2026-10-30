#!/usr/bin/env python3
"""
Zwift Video Monitor
===================

Monitors a Zwift ride (in particular a Zwift Video / Zwift Plus route) on a
Windows PC and collects everything needed to judge whether, and how, the video
content could be served or cached offline:

  * packet capture (headers only) with the built-in Windows ``pktmon`` tool
      - DNS questions/answers        -> which hostnames are used
      - TLS ClientHello SNI          -> which hostnames are used over HTTPS
      - plain HTTP Host/URL          -> which URLs are used over HTTP
      - per-host / per-flow volume   -> where the big (video) traffic goes
      - QUIC (UDP/443) detection     -> HTTP/3 would change the proxy design
  * TCP/UDP connections of the Zwift processes (psutil polling)
      - which process talks to which remote host/port
  * Zwift process disk I/O and open files
      - does Zwift write the video to disk (local cache)?
  * before/after snapshot of the Zwift folders
      - new / grown files during the ride (and where they live)
  * Windows DNS client cache, hosts file, DNS/DoH settings, Zwift version
  * copies of the Zwift log files (Log.txt, Launcher log, prefs.xml)

Everything is written to a time-stamped folder on the Desktop and zipped so it
can be handed over for analysis.

Usage (double click the .exe, or):

    zwift_video_monitor.exe                 interactive: Enter to start/stop
    zwift_video_monitor.exe --duration 600  capture 600 s then stop
    zwift_video_monitor.exe --parse X.pcapng  re-analyse an existing capture
    zwift_video_monitor.exe --no-pcap       don't put the .pcapng in the zip

Administrator rights are required for pktmon (the .exe asks for elevation).
Without them the tool still runs, but without packet capture.
"""

import argparse
import collections
import csv
import ctypes
import datetime as dt
import glob
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
import zipfile

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is bundled in the exe
    psutil = None

VERSION = '0.1.0'
IS_WINDOWS = platform.system() == 'Windows'

# Processes we attribute traffic to. Matched case-insensitively on the
# process name; everything containing 'zwift' is included as well.
ZWIFT_PROCESS_HINTS = ('zwift',)

# Known hostname fragments to classify discovered hosts.
HOST_CLASSES = [
    ('zwift-api', ('us-or-rly101.zwift.com', 'secure.zwift.com', 'launcher.zwift.com',
                   'api.zwift.com', 'relay.zwift.com')),
    ('zwift-cdn', ('cdn.zwift.com',)),
    ('zwift-other', ('zwift.com', 'zwift.io', 'zwiftgame.com')),
    ('cdn-akamai', ('akamai', 'akamaized', 'akamaiedge', 'edgekey', 'edgesuite', 'akadns')),
    ('cdn-cloudfront', ('cloudfront.net', 'amazonaws.com', 'awsglobalaccelerator')),
    ('cdn-fastly', ('fastly', 'fastlylb')),
    ('cdn-cloudflare', ('cloudflare', 'cf-ipfs')),
    ('cdn-google', ('googlevideo', 'gvt1.com', 'googleusercontent', 'gstatic')),
    ('cdn-azure', ('azureedge', 'azurefd', 'windows.net', 'msecnd', 'trafficmanager')),
    ('cdn-mux', ('mux.com', 'litix.io')),
    ('cdn-other', ('cdn', 'edgecast', 'limelight', 'llnwd', 'cachefly', 'bunny', 'b-cdn',
                   'stackpath', 'highwinds', 'keycdn', 'cdn77')),
    ('video-indicator', ('video', 'stream', 'media', 'hls', 'dash', 'rouvy', 'vod', 'mp4')),
    ('telemetry', ('sentry', 'datadog', 'newrelic', 'segment', 'mixpanel', 'amplitude',
                   'braze', 'appsflyer', 'launchdarkly', 'firebase', 'crashlytics',
                   'bugsnag', 'optimizely')),
    ('microsoft', ('microsoft', 'windows', 'msftconnecttest', 'live.com', 'bing', 'office')),
]

VIDEO_PATH_INDICATORS = ('.m3u8', '.mpd', '.ts', '.m4s', '.mp4', '.fmp4', '.cmfv', '.cmfa',
                         '.webm', '.mkv', '/hls', '/dash', '/video', '/stream', '/manifest',
                         'streaming', 'rouvy')


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def now_iso():
    return dt.datetime.now().isoformat(timespec='seconds')


def human(n):
    n = float(n or 0)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or unit == 'TB':
            return '%.1f %s' % (n, unit)
        n /= 1024
    return '%.1f TB' % n


def is_admin():
    if not IS_WINDOWS:
        return hasattr(os, 'geteuid') and os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_cmd(args, timeout=60, shell=False):
    """Run a command, return (returncode, stdout+stderr). Never raises."""
    try:
        kwargs = {}
        if IS_WINDOWS:
            kwargs['creationflags'] = 0x08000000  # CREATE_NO_WINDOW
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           shell=shell, errors='replace', **kwargs)
        return p.returncode, (p.stdout or '') + (p.stderr or '')
    except FileNotFoundError:
        return 127, 'not found: %s' % (args[0] if isinstance(args, list) else args)
    except subprocess.TimeoutExpired:
        return 124, 'timeout'
    except Exception as e:  # pragma: no cover
        return 1, repr(e)


def powershell(script, timeout=60):
    return run_cmd(['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                    '-Command', script], timeout=timeout)


def classify_host(host):
    h = (host or '').lower()
    for label, needles in HOST_CLASSES:
        for n in needles:
            if n in h:
                return label
    return 'unknown'


def is_zwift_proc_name(name):
    n = (name or '').lower()
    return any(h in n for h in ZWIFT_PROCESS_HINTS)


class Log:
    """Print to console and to a log file at the same time."""

    def __init__(self, path=None):
        self.path = path
        self.lock = threading.Lock()
        self.fh = open(path, 'a', encoding='utf-8') if path else None

    def __call__(self, msg):
        line = '[%s] %s' % (dt.datetime.now().strftime('%H:%M:%S'), msg)
        with self.lock:
            print(line, flush=True)
            if self.fh:
                self.fh.write(line + '\n')
                self.fh.flush()

    def close(self):
        if self.fh:
            self.fh.close()


# --------------------------------------------------------------------------
# System information
# --------------------------------------------------------------------------

def zwift_dirs():
    """Candidate Zwift directories (install, documents, appdata)."""
    cands = []
    env = os.environ
    for base in (env.get('ProgramFiles(x86)'), env.get('ProgramFiles'), env.get('ProgramW6432')):
        if base:
            cands.append(os.path.join(base, 'Zwift'))
    userprofile = env.get('USERPROFILE') or os.path.expanduser('~')
    # Documents may be redirected (OneDrive); ask the shell.
    docs = None
    if IS_WINDOWS:
        rc, out = powershell('[Environment]::GetFolderPath("MyDocuments")', timeout=20)
        if rc == 0 and out.strip():
            docs = out.strip().splitlines()[-1].strip()
    if not docs:
        docs = os.path.join(userprofile, 'Documents')
    cands.append(os.path.join(docs, 'Zwift'))
    for base in (env.get('LOCALAPPDATA'), env.get('APPDATA'), env.get('PROGRAMDATA'),
                 os.path.join(env.get('LOCALAPPDATA', ''), 'Low')):
        if base:
            cands.append(os.path.join(base, 'Zwift'))
    # Windows Store / packaged variants
    pk = os.path.join(env.get('LOCALAPPDATA', ''), 'Packages')
    if os.path.isdir(pk):
        for d in os.listdir(pk):
            if 'zwift' in d.lower():
                cands.append(os.path.join(pk, d))
    seen, out = set(), []
    for c in cands:
        c = os.path.normpath(c)
        if c.lower() not in seen and os.path.isdir(c):
            seen.add(c.lower())
            out.append(c)
    return out, docs


def read_text(path, limit=200000):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read(limit)
    except Exception as e:
        return '<<unreadable: %r>>' % e


def zwift_version(dirs):
    info = {}
    for d in dirs:
        p = os.path.join(d, 'Zwift_ver_cur.xml')
        if os.path.isfile(p):
            txt = read_text(p, 5000)
            info['Zwift_ver_cur.xml'] = txt
            m = re.search(r'sversion="([^"]+)"', txt)
            if m:
                info['version'] = m.group(1)
        p = os.path.join(d, 'Zwift_ver_cur_filename.txt')
        if os.path.isfile(p):
            info['Zwift_ver_cur_filename.txt'] = read_text(p, 500)
        for exe in ('ZwiftApp.exe', 'ZwiftLauncher.exe'):
            p = os.path.join(d, exe)
            if os.path.isfile(p):
                st = os.stat(p)
                info[exe] = {'size': st.st_size,
                             'mtime': dt.datetime.fromtimestamp(st.st_mtime).isoformat()}
    return info


def collect_system_info(log, dirs, docs):
    log('Collecting system information ...')
    info = {
        'tool_version': VERSION,
        'timestamp': now_iso(),
        'platform': platform.platform(),
        'python': sys.version,
        'is_admin': is_admin(),
        'hostname': socket.gethostname(),
        'zwift_dirs': dirs,
        'documents_dir': docs,
        'zwift': zwift_version(dirs),
    }
    if psutil:
        try:
            info['interfaces'] = {
                k: [{'family': str(a.family), 'address': a.address, 'netmask': a.netmask}
                    for a in v] for k, v in psutil.net_if_addrs().items()}
        except Exception as e:
            info['interfaces_error'] = repr(e)
    if IS_WINDOWS:
        hosts = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                             'System32', 'drivers', 'etc', 'hosts')
        info['hosts_file'] = read_text(hosts, 20000)
        cmds = {
            'ipconfig_all': (['ipconfig', '/all'], False),
            'route_print': (['route', 'print', '-4'], False),
            'pktmon_help': (['pktmon', 'help'], False),
            'dns_servers': ('Get-DnsClientServerAddress | Format-List', True),
            'dns_doh': ('Get-DnsClientDohServerAddress | Format-List', True),
            'proxy_settings': ('Get-ItemProperty "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" | Select-Object ProxyEnable,ProxyServer,AutoConfigURL | Format-List', True),
            'winhttp_proxy': (['netsh', 'winhttp', 'show', 'proxy'], False),
            'os_version': ('Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | Format-List', True),
            'zwift_uninstall_reg': ('Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*Zwift*" } | Select-Object DisplayName,DisplayVersion,InstallLocation | Format-List', True),
        }
        for key, (cmd, ps) in cmds.items():
            rc, out = powershell(cmd) if ps else run_cmd(cmd)
            info[key] = {'rc': rc, 'output': out[-20000:]}
    return info


# --------------------------------------------------------------------------
# File snapshot
# --------------------------------------------------------------------------

def snapshot_dirs(dirs, log, max_files=400000):
    """Return {path: (size, mtime)} for all files under dirs."""
    snap = {}
    count = 0
    for d in dirs:
        for root, subdirs, files in os.walk(d):
            for f in files:
                p = os.path.join(root, f)
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                snap[p] = (st.st_size, st.st_mtime)
                count += 1
                if count >= max_files:
                    log('Snapshot: file limit reached (%d), stopping walk' % max_files)
                    return snap
    log('Snapshot: %d files, %s' % (len(snap), human(sum(s for s, _ in snap.values()))))
    return snap


def diff_snapshots(before, after):
    changes = []
    for p, (size, mtime) in after.items():
        if p not in before:
            changes.append({'path': p, 'change': 'new', 'size': size, 'delta': size,
                            'mtime': dt.datetime.fromtimestamp(mtime).isoformat()})
        else:
            osize, omtime = before[p]
            if size != osize or mtime != omtime:
                changes.append({'path': p, 'change': 'modified', 'size': size,
                                'delta': size - osize,
                                'mtime': dt.datetime.fromtimestamp(mtime).isoformat()})
    for p, (size, _) in before.items():
        if p not in after:
            changes.append({'path': p, 'change': 'deleted', 'size': 0, 'delta': -size,
                            'mtime': ''})
    changes.sort(key=lambda c: -abs(c['delta']))
    return changes


# --------------------------------------------------------------------------
# Process / connection polling
# --------------------------------------------------------------------------

class ProcessMonitor(threading.Thread):
    def __init__(self, log, interval=2.0, dns_interval=30.0, files_interval=10.0):
        super().__init__(daemon=True)
        self.log = log
        self.interval = interval
        self.dns_interval = dns_interval
        self.files_interval = files_interval
        self.stop_event = threading.Event()
        self.connections = {}     # key -> dict
        self.processes = {}       # pid -> dict
        self.open_files = {}      # path -> dict
        self.samples = []         # periodic totals
        self.dns_cache = {}       # name -> set(ips)
        self.dns_cache_raw = []
        self.ip_to_pid = {}       # 'ip:port' -> (pid, name)
        self.errors = collections.Counter()

    def run(self):
        last_dns = 0
        last_files = 0
        while not self.stop_event.is_set():
            t0 = time.time()
            try:
                self.poll_processes()
            except Exception as e:
                self.errors['poll_processes:' + e.__class__.__name__] += 1
            if IS_WINDOWS and t0 - last_dns >= self.dns_interval:
                last_dns = t0
                try:
                    self.poll_dns_cache()
                except Exception as e:
                    self.errors['poll_dns:' + e.__class__.__name__] += 1
            if t0 - last_files >= self.files_interval:
                last_files = t0
                try:
                    self.poll_open_files()
                except Exception as e:
                    self.errors['poll_files:' + e.__class__.__name__] += 1
            self.stop_event.wait(max(0.2, self.interval - (time.time() - t0)))

    def zwift_pids(self):
        pids = {}
        for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
            try:
                if is_zwift_proc_name(p.info['name']) or is_zwift_proc_name(p.info['exe']):
                    pids[p.pid] = p
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return pids

    def poll_processes(self):
        ts = now_iso()
        procs = self.zwift_pids()
        sample = {'ts': ts, 'net': {}, 'procs': {}}
        try:
            n = psutil.net_io_counters()
            sample['net'] = {'bytes_sent': n.bytes_sent, 'bytes_recv': n.bytes_recv}
        except Exception:
            pass
        for pid, p in procs.items():
            try:
                with p.oneshot():
                    name = p.name()
                    entry = self.processes.setdefault(pid, {
                        'pid': pid, 'name': name, 'exe': p.info.get('exe'),
                        'cmdline': ' '.join(p.info.get('cmdline') or [])[:500],
                        'first_seen': ts, 'create_time': dt.datetime.fromtimestamp(
                            p.info.get('create_time') or 0).isoformat()})
                    entry['last_seen'] = ts
                    try:
                        io = p.io_counters()
                        entry['io'] = {'read_bytes': io.read_bytes, 'write_bytes': io.write_bytes,
                                       'other_bytes': getattr(io, 'other_bytes', 0)}
                        sample['procs'][pid] = {'name': name, 'write_bytes': io.write_bytes,
                                                'read_bytes': io.read_bytes,
                                                'rss': p.memory_info().rss,
                                                'cpu': p.cpu_percent(None)}
                    except (psutil.AccessDenied, AttributeError):
                        pass
                    try:
                        conns = p.net_connections(kind='inet')
                    except AttributeError:
                        conns = p.connections(kind='inet')
                    for c in conns:
                        if not c.raddr:
                            continue
                        key = (pid, c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port,
                               'tcp' if c.type == socket.SOCK_STREAM else 'udp')
                        e = self.connections.get(key)
                        if e is None:
                            e = {'pid': pid, 'process': name, 'laddr': c.laddr.ip,
                                 'lport': c.laddr.port, 'raddr': c.raddr.ip,
                                 'rport': c.raddr.port,
                                 'proto': key[5], 'first_seen': ts, 'statuses': set()}
                            self.connections[key] = e
                        e['last_seen'] = ts
                        e['statuses'].add(c.status)
                        self.ip_to_pid['%s:%s' % (c.laddr.ip, c.laddr.port)] = (pid, name)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        self.samples.append(sample)

    def poll_open_files(self):
        ts = now_iso()
        for pid, p in self.zwift_pids().items():
            try:
                for f in p.open_files():
                    e = self.open_files.setdefault(f.path, {'path': f.path, 'pid': pid,
                                                            'process': p.name(),
                                                            'first_seen': ts, 'count': 0})
                    e['last_seen'] = ts
                    e['count'] += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def poll_dns_cache(self):
        rc, out = powershell('Get-DnsClientCache | Select-Object Entry,Name,Type,Data,TimeToLive | ConvertTo-Json -Compress', timeout=60)
        if rc != 0 or not out.strip():
            return
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return
        if isinstance(data, dict):
            data = [data]
        for e in data:
            name = (e.get('Entry') or e.get('Name') or '').rstrip('.').lower()
            val = e.get('Data')
            if not name or not val:
                continue
            self.dns_cache.setdefault(name, set()).add(str(val))
        self.dns_cache_raw.append({'ts': now_iso(), 'entries': len(data)})

    def stop(self):
        self.stop_event.set()

    def export(self):
        conns = []
        for e in self.connections.values():
            d = dict(e)
            d['statuses'] = ','.join(sorted(d['statuses']))
            conns.append(d)
        conns.sort(key=lambda c: (c['process'], c['raddr'], c['rport']))
        return {
            'processes': list(self.processes.values()),
            'connections': conns,
            'open_files': sorted(self.open_files.values(), key=lambda f: f['path']),
            'samples': self.samples,
            'dns_client_cache': {k: sorted(v) for k, v in self.dns_cache.items()},
            'errors': dict(self.errors),
        }


# --------------------------------------------------------------------------
# pktmon control
# --------------------------------------------------------------------------

class Pktmon:
    def __init__(self, log, outdir, pkt_size=700, file_size_mb=1024):
        self.log = log
        self.outdir = outdir
        self.etl = os.path.join(outdir, 'capture.etl')
        self.pkt_size = pkt_size
        self.file_size_mb = file_size_mb
        self.started = False
        self.available = IS_WINDOWS and shutil.which('pktmon') is not None
        self.info = {}

    def start(self):
        if not self.available:
            self.log('pktmon not available on this system; packet capture disabled')
            return False
        if not is_admin():
            self.log('Not running as administrator; packet capture disabled')
            return False
        run_cmd(['pktmon', 'stop'])
        run_cmd(['pktmon', 'filter', 'remove'])
        args = ['pktmon', 'start', '--capture', '--comp', 'nics',
                '--pkt-size', str(self.pkt_size),
                '--file-name', self.etl,
                '--file-size', str(self.file_size_mb),
                '--log-mode', 'multi-file']
        rc, out = run_cmd(args)
        self.info['start'] = {'args': args, 'rc': rc, 'output': out}
        if rc != 0:
            # older pktmon versions: fall back to minimal syntax
            args = ['pktmon', 'start', '--etw', '-p', '0', '-f', self.etl, '-s', str(self.file_size_mb)]
            rc, out = run_cmd(args)
            self.info['start_fallback'] = {'args': args, 'rc': rc, 'output': out}
        if rc != 0:
            self.log('pktmon start failed: %s' % out.strip()[:300])
            return False
        self.started = True
        self.log('Packet capture started (pktmon, %d bytes per packet, file %s)' % (self.pkt_size, self.etl))
        return True

    def stop(self):
        if not self.started:
            return []
        rc, out = run_cmd(['pktmon', 'stop'], timeout=180)
        self.info['stop'] = {'rc': rc, 'output': out}
        self.started = False
        self.log('Packet capture stopped')
        etls = sorted(glob.glob(os.path.join(self.outdir, 'capture*.etl')))
        pcaps = []
        for i, etl in enumerate(etls):
            pcap = os.path.join(self.outdir, 'capture%s.pcapng' % ('' if i == 0 else '_%d' % i))
            rc, out = run_cmd(['pktmon', 'etl2pcap', etl, '--out', pcap], timeout=1800)
            if rc != 0 or not os.path.isfile(pcap):
                rc, out = run_cmd(['pktmon', 'pcapng', etl, '-o', pcap], timeout=1800)
            self.info.setdefault('etl2pcap', []).append({'etl': etl, 'rc': rc, 'output': out[-2000:]})
            if os.path.isfile(pcap):
                pcaps.append(pcap)
                self.log('Converted %s -> %s (%s)' % (os.path.basename(etl), os.path.basename(pcap),
                                                       human(os.path.getsize(pcap))))
                try:
                    os.remove(etl)
                except OSError:
                    pass
            else:
                self.log('etl2pcap failed for %s: %s' % (etl, out.strip()[:200]))
        return pcaps


# --------------------------------------------------------------------------
# pcap / pcapng parsing (pure python)
# --------------------------------------------------------------------------

def iter_packets(path):
    """Yield (timestamp, linktype, data) for pcap and pcapng files."""
    with open(path, 'rb') as f:
        magic = f.read(4)
        f.seek(0)
        if magic == b'\x0a\x0d\x0d\x0a':
            yield from _iter_pcapng(f)
        elif magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'):
            yield from _iter_pcap(f, magic)
        else:
            raise ValueError('Unknown capture format: %r' % magic)


def _iter_pcap(f, magic):
    endian = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    hdr = f.read(24)
    linktype = struct.unpack(endian + 'I', hdr[20:24])[0]
    while True:
        ph = f.read(16)
        if len(ph) < 16:
            return
        ts_sec, ts_usec, incl, _orig = struct.unpack(endian + 'IIII', ph)
        data = f.read(incl)
        if len(data) < incl:
            return
        yield ts_sec + ts_usec / 1e6, linktype, data


def _iter_pcapng(f):
    endian = '<'
    linktypes = {}
    tsres = {}
    while True:
        bh = f.read(8)
        if len(bh) < 8:
            return
        btype, blen = struct.unpack(endian + 'II', bh)
        if btype == 0x0A0D0D0A:
            body = f.read(blen - 12)
            if len(body) < blen - 12:
                return
            bom = body[:4]
            if bom == b'\x1a\x2b\x3c\x4d':
                endian = '<'
            elif bom == b'\x4d\x3c\x2b\x1a':
                endian = '>'
                blen = struct.unpack('>I', bh[4:8])[0]
                body = body + f.read(blen - 12 - len(body))
            f.read(4)
            linktypes, tsres = {}, {}
            continue
        if blen < 12:
            return
        body = f.read(blen - 12)
        trailer = f.read(4)
        if len(body) < blen - 12 or len(trailer) < 4:
            return
        if btype == 1:  # IDB
            lt = struct.unpack(endian + 'H', body[:2])[0]
            idx = len(linktypes)
            linktypes[idx] = lt
            res = 1e-6
            # options: if_tsresol (code 9)
            pos = 8
            while pos + 4 <= len(body):
                code, olen = struct.unpack(endian + 'HH', body[pos:pos + 4])
                val = body[pos + 4:pos + 4 + olen]
                if code == 0:
                    break
                if code == 9 and olen >= 1:
                    v = val[0]
                    res = 2.0 ** -(v & 0x7f) if v & 0x80 else 10.0 ** -v
                pos += 4 + ((olen + 3) & ~3)
            tsres[idx] = res
        elif btype == 6:  # EPB
            iface, tsh, tsl, caplen, _origlen = struct.unpack(endian + 'IIIII', body[:20])
            data = body[20:20 + caplen]
            ts = ((tsh << 32) | tsl) * tsres.get(iface, 1e-6)
            yield ts, linktypes.get(iface, 1), data
        elif btype == 3:  # SPB
            origlen = struct.unpack(endian + 'I', body[:4])[0]
            data = body[4:4 + origlen]
            yield 0.0, linktypes.get(0, 1), data


def parse_dns_name(data, pos, depth=0):
    labels = []
    jumped = False
    end = pos
    while pos < len(data) and depth < 20:
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                end = pos + 2
            jumped = True
            pos = ptr
            depth += 1
            continue
        pos += 1
        labels.append(data[pos:pos + length].decode('ascii', 'replace'))
        pos += length
    if not jumped:
        end = pos
    return '.'.join(labels).lower(), end


def parse_dns(payload):
    """Return (questions, answers) with answers as list of (name, type, value)."""
    try:
        tid, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', payload[:12])
    except struct.error:
        return [], []
    pos = 12
    questions = []
    for _ in range(qd):
        name, pos = parse_dns_name(payload, pos)
        if pos + 4 > len(payload):
            return questions, []
        qtype = struct.unpack('!H', payload[pos:pos + 2])[0]
        pos += 4
        questions.append((name, qtype))
    answers = []
    for _ in range(an + ns):
        if pos >= len(payload):
            break
        name, pos = parse_dns_name(payload, pos)
        if pos + 10 > len(payload):
            break
        rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', payload[pos:pos + 10])
        pos += 10
        rdata = payload[pos:pos + rdlen]
        if rtype == 1 and rdlen == 4:
            answers.append((name, 'A', socket.inet_ntoa(rdata)))
        elif rtype == 28 and rdlen == 16:
            answers.append((name, 'AAAA', str(ipaddress.IPv6Address(rdata))))
        elif rtype == 5:
            cname, _ = parse_dns_name(payload, pos)
            answers.append((name, 'CNAME', cname))
        pos += rdlen
    return questions, answers


def parse_tls_client_hello(payload):
    """Return SNI hostname if payload starts with a TLS ClientHello, else None.

    Returns the string 'TLS-ClientHello-no-SNI' if it is a ClientHello without
    a (readable) server name, and None if it is not a ClientHello at all.
    """
    if len(payload) < 11 or payload[0] != 0x16 or payload[1] != 0x03 or payload[5] != 0x01:
        return None
    try:
        pos = 9  # record header(5) + handshake header(4)
        pos += 2 + 32  # version + random
        sid_len = payload[pos]
        pos += 1 + sid_len
        cs_len = struct.unpack('!H', payload[pos:pos + 2])[0]
        pos += 2 + cs_len
        cm_len = payload[pos]
        pos += 1 + cm_len
        if pos + 2 > len(payload):
            return 'TLS-ClientHello-no-SNI'
        ext_total = struct.unpack('!H', payload[pos:pos + 2])[0]
        pos += 2
        end = min(len(payload), pos + ext_total)
        while pos + 4 <= end:
            etype, elen = struct.unpack('!HH', payload[pos:pos + 4])
            pos += 4
            if etype == 0:  # server_name
                p = pos + 2
                while p + 3 <= pos + elen and p + 3 <= len(payload):
                    ntype = payload[p]
                    nlen = struct.unpack('!H', payload[p + 1:p + 3])[0]
                    p += 3
                    if ntype == 0:
                        return payload[p:p + nlen].decode('ascii', 'replace').lower()
                    p += nlen
            if etype == 0xfe0d:  # encrypted_client_hello
                return 'TLS-ClientHello-ECH'
            pos += elen
    except (struct.error, IndexError):
        pass
    return 'TLS-ClientHello-no-SNI'


HTTP_METHODS = (b'GET ', b'POST ', b'HEAD ', b'PUT ', b'OPTIONS ', b'DELETE ', b'PATCH ', b'CONNECT ')


def parse_http_request(payload):
    if not payload.startswith(HTTP_METHODS):
        return None
    try:
        head = payload.split(b'\r\n\r\n', 1)[0].decode('latin-1')
    except Exception:
        return None
    lines = head.split('\r\n')
    req = lines[0]
    host = None
    for line in lines[1:]:
        if line.lower().startswith('host:'):
            host = line.split(':', 1)[1].strip()
            break
    return {'request': req[:400], 'host': host}


def parse_http_response_ct(payload):
    if not payload.startswith(b'HTTP/1.'):
        return None
    head = payload.split(b'\r\n\r\n', 1)[0].decode('latin-1', 'replace')
    ct = None
    for line in head.split('\r\n')[1:]:
        if line.lower().startswith('content-type:'):
            ct = line.split(':', 1)[1].strip()
    return {'status': head.split('\r\n')[0][:100], 'content_type': ct}


def is_quic_initial(payload):
    # Long header, fixed bit set, version != 0 (very loose heuristic)
    return len(payload) > 5 and (payload[0] & 0xC0) == 0xC0


class CaptureAnalysis:
    """Aggregates a capture into hosts/flows."""

    def __init__(self, local_ips):
        self.local_ips = set(local_ips)
        self.dns_names = {}            # ip -> set(names)
        self.dns_queries = collections.Counter()
        self.dns_answers = []
        self.cnames = {}               # alias -> target
        self.sni = {}                  # (ip, port) -> Counter(sni)
        self.http_requests = []
        self.http_hosts = {}           # ip -> set(host)
        self.flows = {}                # (proto, rip, rport, lport) -> dict
        self.quic_flows = set()
        self.packets = 0
        self.unparsed = 0
        self.first_ts = None
        self.last_ts = None
        self.bytes_total = 0

    # -- helpers
    def _flow(self, proto, lip, lport, rip, rport):
        key = (proto, rip, rport, lip, lport)
        fl = self.flows.get(key)
        if fl is None:
            fl = {'proto': proto, 'laddr': lip, 'lport': lport, 'raddr': rip, 'rport': rport,
                  'bytes_in': 0, 'bytes_out': 0, 'pkts_in': 0, 'pkts_out': 0,
                  'first_ts': None, 'last_ts': None, 'sni': None, 'http_host': None}
            self.flows[key] = fl
        return fl

    def feed(self, ts, linktype, data):
        self.packets += 1
        if self.first_ts is None or (ts and ts < self.first_ts):
            self.first_ts = ts
        if ts and (self.last_ts is None or ts > self.last_ts):
            self.last_ts = ts
        try:
            self._parse(ts, linktype, data)
        except Exception:
            self.unparsed += 1

    def _parse(self, ts, linktype, data):
        if linktype == 1:  # Ethernet
            if len(data) < 14:
                return
            ethertype = struct.unpack('!H', data[12:14])[0]
            off = 14
            while ethertype in (0x8100, 0x88a8) and len(data) >= off + 4:
                ethertype = struct.unpack('!H', data[off + 2:off + 4])[0]
                off += 4
            if ethertype == 0x0800:
                self._parse_ipv4(ts, data[off:])
            elif ethertype == 0x86DD:
                self._parse_ipv6(ts, data[off:])
        elif linktype == 101 or linktype == 228:  # RAW IP / IPv4
            self._parse_ipv4(ts, data) if data and (data[0] >> 4) == 4 else self._parse_ipv6(ts, data)
        elif linktype == 229:
            self._parse_ipv6(ts, data)
        elif linktype == 113:  # Linux SLL
            ethertype = struct.unpack('!H', data[14:16])[0]
            if ethertype == 0x0800:
                self._parse_ipv4(ts, data[16:])
            elif ethertype == 0x86DD:
                self._parse_ipv6(ts, data[16:])
        else:
            self.unparsed += 1

    def _parse_ipv4(self, ts, pkt):
        if len(pkt) < 20 or (pkt[0] >> 4) != 4:
            return
        ihl = (pkt[0] & 0x0F) * 4
        total_len = struct.unpack('!H', pkt[2:4])[0]
        proto = pkt[9]
        src = socket.inet_ntoa(pkt[12:16])
        dst = socket.inet_ntoa(pkt[16:20])
        frag = struct.unpack('!H', pkt[6:8])[0] & 0x1FFF
        if frag:
            return
        self._parse_l4(ts, proto, src, dst, pkt[ihl:], total_len)

    def _parse_ipv6(self, ts, pkt):
        if len(pkt) < 40 or (pkt[0] >> 4) != 6:
            return
        plen = struct.unpack('!H', pkt[4:6])[0]
        nh = pkt[6]
        src = str(ipaddress.IPv6Address(pkt[8:24]))
        dst = str(ipaddress.IPv6Address(pkt[24:40]))
        self._parse_l4(ts, nh, src, dst, pkt[40:], plen + 40)

    def _direction(self, src, dst):
        if src in self.local_ips and dst not in self.local_ips:
            return 'out'
        if dst in self.local_ips and src not in self.local_ips:
            return 'in'
        # fall back: private -> public is out
        try:
            s, d = ipaddress.ip_address(src), ipaddress.ip_address(dst)
            if s.is_private and not d.is_private:
                return 'out'
            if d.is_private and not s.is_private:
                return 'in'
        except ValueError:
            pass
        return None

    def _parse_l4(self, ts, proto, src, dst, seg, total_len):
        if proto == 6:
            if len(seg) < 20:
                return
            sport, dport = struct.unpack('!HH', seg[:4])
            doff = (seg[12] >> 4) * 4
            payload = seg[doff:]
            pname = 'tcp'
        elif proto == 17:
            if len(seg) < 8:
                return
            sport, dport = struct.unpack('!HH', seg[:4])
            payload = seg[8:]
            pname = 'udp'
        else:
            return
        direction = self._direction(src, dst)
        if direction is None:
            return
        if direction == 'out':
            lip, lport, rip, rport = src, sport, dst, dport
        else:
            lip, lport, rip, rport = dst, dport, src, sport
        self.bytes_total += total_len
        fl = self._flow(pname, lip, lport, rip, rport)
        fl['bytes_' + direction] += total_len
        fl['pkts_' + direction] += 1
        if fl['first_ts'] is None:
            fl['first_ts'] = ts
        fl['last_ts'] = ts

        if pname == 'udp' and (sport == 53 or dport == 53) and payload:
            q, a = parse_dns(payload)
            if direction == 'out':
                for name, qtype in q:
                    self.dns_queries[name] += 1
            for name, rtype, val in a:
                if rtype in ('A', 'AAAA'):
                    self.dns_names.setdefault(val, set()).add(name)
                elif rtype == 'CNAME':
                    self.cnames[name] = val
                self.dns_answers.append({'ts': ts, 'name': name, 'type': rtype, 'value': val})
            return
        if not payload:
            return
        if pname == 'tcp':
            if direction == 'out':
                sni = parse_tls_client_hello(payload)
                if sni:
                    self.sni.setdefault((rip, rport), collections.Counter())[sni] += 1
                    if not sni.startswith('TLS-ClientHello'):
                        fl['sni'] = sni
                    return
                hr = parse_http_request(payload)
                if hr:
                    fl['http_host'] = hr['host']
                    if hr['host']:
                        self.http_hosts.setdefault(rip, set()).add(hr['host'])
                    if len(self.http_requests) < 20000:
                        self.http_requests.append({'ts': ts, 'raddr': rip, 'rport': rport,
                                                   'host': hr['host'], 'request': hr['request']})
            else:
                resp = parse_http_response_ct(payload)
                if resp and resp.get('content_type'):
                    fl.setdefault('http_content_types', set()).add(resp['content_type'])
        elif pname == 'udp' and direction == 'out' and rport == 443 and is_quic_initial(payload):
            self.quic_flows.add((rip, rport))

    # -- resolution
    def resolve_cname_chain(self, name, depth=0):
        names = {name}
        cur = name
        while cur in self.cnames and depth < 10:
            cur = self.cnames[cur]
            names.add(cur)
            depth += 1
        return names

    def names_for_ip(self, ip, extra=None):
        names = set()
        for n in self.dns_names.get(ip, ()):
            names |= self.resolve_cname_chain(n)
        # reverse cname: aliases pointing to a name that resolved to ip
        for alias, target in self.cnames.items():
            if target in names:
                names.add(alias)
        if extra:
            names |= set(extra.get(ip, ()))
        return names

    def summarize(self, proc_conns=None, dns_client_cache=None, reverse_dns=True, log=None):
        # Build ip -> names from the windows dns client cache as well
        extra = {}
        for name, vals in (dns_client_cache or {}).items():
            for v in vals:
                try:
                    ipaddress.ip_address(v)
                    extra.setdefault(v, set()).add(name)
                except ValueError:
                    self.cnames.setdefault(name, v.lower())
        # Map local port -> process from psutil polling
        port_proc = {}
        for c in (proc_conns or []):
            port_proc[(c['proto'], c['laddr'], c['lport'], c['raddr'], c['rport'])] = c['process']
            port_proc[(c['proto'], c['lport'], c['raddr'], c['rport'])] = c['process']
        hosts = {}
        for key, fl in self.flows.items():
            proto, rip, rport, lip, lport = key
            proc = port_proc.get((proto, lip, lport, rip, rport)) or port_proc.get((proto, lport, rip, rport))
            fl['process'] = proc
            names = set()
            if fl.get('sni'):
                names.add(fl['sni'])
            if fl.get('http_host'):
                names.add(fl['http_host'])
            for n, cnt in self.sni.get((rip, rport), {}).items():
                if not n.startswith('TLS-ClientHello'):
                    names.add(n)
            names |= self.names_for_ip(rip, extra)
            names |= set(self.http_hosts.get(rip, ()))
            fl['names'] = sorted(names)
            h = hosts.get(rip)
            if h is None:
                h = {'ip': rip, 'names': set(), 'bytes_in': 0, 'bytes_out': 0, 'pkts': 0,
                     'flows': 0, 'ports': collections.Counter(), 'processes': set(),
                     'quic': False, 'sni_notes': set(), 'http_content_types': set()}
                hosts[rip] = h
            h['names'] |= names
            h['bytes_in'] += fl['bytes_in']
            h['bytes_out'] += fl['bytes_out']
            h['pkts'] += fl['pkts_in'] + fl['pkts_out']
            h['flows'] += 1
            h['ports']['%s/%s' % (proto, rport)] += 1
            if proc:
                h['processes'].add(proc)
            if (rip, rport) in self.quic_flows:
                h['quic'] = True
            for n in self.sni.get((rip, rport), {}):
                if n.startswith('TLS-ClientHello'):
                    h['sni_notes'].add(n)
            h['http_content_types'] |= fl.get('http_content_types', set())
        # Reverse DNS for the heavier unknown hosts
        if reverse_dns:
            heavy = sorted(hosts.values(), key=lambda h: -(h['bytes_in'] + h['bytes_out']))[:60]
            for h in heavy:
                if h['names']:
                    continue
                try:
                    socket.setdefaulttimeout(2.0)
                    h['rdns'] = socket.gethostbyaddr(h['ip'])[0]
                except Exception:
                    h['rdns'] = None
        out = []
        for h in hosts.values():
            names = sorted(h['names'])
            label = names[0] if names else (h.get('rdns') or h['ip'])
            out.append({
                'ip': h['ip'], 'names': names, 'rdns': h.get('rdns'),
                'label': label,
                'class': classify_host(' '.join(names + [h.get('rdns') or ''])),
                'bytes_in': h['bytes_in'], 'bytes_out': h['bytes_out'],
                'bytes_total': h['bytes_in'] + h['bytes_out'],
                'pkts': h['pkts'], 'flows': h['flows'],
                'ports': dict(h['ports']),
                'processes': sorted(h['processes']),
                'quic': h['quic'], 'sni_notes': sorted(h['sni_notes']),
                'http_content_types': sorted(h['http_content_types']),
            })
        out.sort(key=lambda h: -h['bytes_total'])
        return out


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def write_json(path, obj):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, default=str)


def write_csv(path, rows, fields):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        for r in rows:
            w.writerow({k: (','.join(map(str, v)) if isinstance(v, (list, set, tuple))
                            else json.dumps(v) if isinstance(v, dict) else v)
                        for k, v in r.items()})


def build_text_report(ctx):
    L = []
    a = L.append
    a('Zwift Video Monitor report  (tool %s)' % VERSION)
    a('Generated: %s' % now_iso())
    si = ctx.get('system_info', {})
    a('Platform: %s   admin: %s' % (si.get('platform'), si.get('is_admin')))
    zw = si.get('zwift', {})
    a('Zwift version: %s' % zw.get('version', '?'))
    a('Zwift dirs: %s' % ', '.join(si.get('zwift_dirs', [])))
    cap = ctx.get('capture', {})
    a('')
    a('== Capture ==')
    a('Started: %s   stopped: %s   duration: %s s' % (ctx.get('started'), ctx.get('stopped'), ctx.get('duration_s')))
    a('Packet capture: %s' % ('yes (%d packets, %s)' % (cap.get('packets', 0), human(cap.get('bytes_total', 0)))
                              if cap.get('packets') else 'NO (%s)' % cap.get('reason', 'unknown')))
    net = ctx.get('net_delta')
    if net:
        a('System network counters during ride: recv %s, sent %s' % (human(net['recv']), human(net['sent'])))
    a('')
    a('== Zwift processes ==')
    for p in ctx.get('process_data', {}).get('processes', []):
        io = p.get('io', {})
        a('  pid %-6s %-28s disk read %-10s disk write %-10s  exe=%s' % (
            p['pid'], p['name'], human(io.get('read_bytes', 0)), human(io.get('write_bytes', 0)), p.get('exe')))
    pio = ctx.get('process_io_delta', {})
    if pio:
        a('  Disk I/O delta during ride (per process):')
        for name, d in pio.items():
            a('    %-28s read +%s  write +%s' % (name, human(d['read']), human(d['write'])))
    a('')
    a('== Top hosts by volume (from packet capture) ==')
    hosts = ctx.get('hosts', [])
    if not hosts:
        a('  (no packet capture)')
    a('  %-10s %-10s %-6s %-16s %-16s %-14s %s' % ('in', 'out', 'quic', 'class', 'process', 'ip', 'names'))
    for h in hosts[:40]:
        a('  %-10s %-10s %-6s %-16s %-16s %-14s %s' % (
            human(h['bytes_in']), human(h['bytes_out']), 'QUIC' if h['quic'] else '',
            h['class'], ','.join(h['processes'])[:16], h['ip'],
            ', '.join(h['names'][:4]) + (' (rdns: %s)' % h['rdns'] if h.get('rdns') else '')))
    a('')
    a('== Hosts contacted by Zwift processes (psutil) ==')
    byhost = collections.defaultdict(lambda: {'ports': set(), 'procs': set(), 'n': 0})
    for c in ctx.get('process_data', {}).get('connections', []):
        e = byhost[c['raddr']]
        e['ports'].add('%s/%s' % (c['proto'], c['rport']))
        e['procs'].add(c['process'])
        e['n'] += 1
    hostmap = {h['ip']: h for h in hosts}
    for ip, e in sorted(byhost.items(), key=lambda kv: -kv[1]['n']):
        names = hostmap.get(ip, {}).get('names', [])
        a('  %-40s %-16s conns=%-4d ports=%s procs=%s' % (ip, ', '.join(names[:2])[:40], e['n'],
                                                        ','.join(sorted(e['ports'])), ','.join(sorted(e['procs']))))
    a('')
    a('== DNS names queried (top 60) ==')
    for name, n in sorted(cap.get('dns_queries', {}).items(), key=lambda kv: -kv[1])[:60]:
        a('  %5d  %-60s %s' % (n, name, classify_host(name)))
    a('')
    a('== Plain HTTP requests (first 50) ==')
    for r in cap.get('http_requests', [])[:50]:
        a('  %s %s  -> %s' % (r['host'], r['request'], r['raddr']))
    a('')
    a('== Files changed in Zwift folders during the ride (top 60 by size delta) ==')
    tot_new = sum(c['delta'] for c in ctx.get('file_changes', []) if c['delta'] > 0)
    a('  total growth: %s, %d changed files' % (human(tot_new), len(ctx.get('file_changes', []))))
    for c in ctx.get('file_changes', [])[:60]:
        a('  %-9s %+12s  %12s  %s' % (c['change'], human(c['delta']) if c['delta'] >= 0 else '-' + human(-c['delta']),
                                      human(c['size']), c['path']))
    a('')
    a('== Files Zwift had open during the ride (video-ish extensions first) ==')
    files = ctx.get('process_data', {}).get('open_files', [])
    vid = [f for f in files if any(k in f['path'].lower() for k in VIDEO_PATH_INDICATORS)]
    for f in vid[:40] + [f for f in files if f not in vid][:40]:
        a('  %-20s %s' % (f['process'], f['path']))
    a('')
    a('== Verdict helpers ==')
    big = [h for h in hosts if h['bytes_in'] > 50 * 1024 * 1024]
    if big:
        a('Hosts that delivered > 50 MB (video candidates):')
        for h in big:
            a('  %-10s %-14s %-16s %s%s' % (human(h['bytes_in']), h['ip'], h['class'],
                                             ', '.join(h['names'][:3]) or h.get('rdns') or '?',
                                             '  [QUIC/HTTP3]' if h['quic'] else ''))
    else:
        a('No host delivered more than 50 MB. Either the ride was too short, the video was')
        a('already cached locally, or the capture missed the traffic (VPN? other adapter?).')
    if tot_new > 100 * 1024 * 1024:
        a('Zwift folders grew by %s during the ride -> video seems to be stored on disk (look at the')
        a('file list above). That is the most promising route for offline use.' % human(tot_new))
    else:
        a('Zwift folders grew by only %s -> video is streamed, not stored (or stored elsewhere).' % human(tot_new))
    return '\n'.join(L)


# --------------------------------------------------------------------------
# Main flows
# --------------------------------------------------------------------------

def copy_zwift_logs(dirs, docs, outdir, log):
    dest = os.path.join(outdir, 'zwift_logs')
    os.makedirs(dest, exist_ok=True)
    copied = []
    patterns = []
    zdocs = os.path.join(docs, 'Zwift')
    patterns += [os.path.join(zdocs, 'Logs', '*.txt'), os.path.join(zdocs, 'prefs.xml'),
                 os.path.join(zdocs, 'Logs', '*.log')]
    for d in dirs:
        patterns += [os.path.join(d, 'Logs', '*.txt'), os.path.join(d, '*.log'),
                     os.path.join(d, 'Zwift_ver_cur.xml'), os.path.join(d, 'Zwift_ver_cur_filename.txt'),
                     os.path.join(d, 'ZwiftLauncher.exe.config'), os.path.join(d, 'Zwift_StreamingFiles*.xml'),
                     os.path.join(d, 'assets', 'Streaming', '*.xml')]
    cutoff = time.time() - 2 * 86400
    for pat in patterns:
        for p in glob.glob(pat):
            try:
                st = os.stat(p)
                if st.st_mtime < cutoff and not p.lower().endswith(('.xml', '.config')):
                    continue
                if st.st_size > 200 * 1024 * 1024:
                    continue
                name = os.path.relpath(p, os.path.dirname(os.path.dirname(p))).replace(os.sep, '__')
                shutil.copy2(p, os.path.join(dest, name))
                copied.append(p)
            except Exception as e:
                log('Could not copy %s: %r' % (p, e))
    log('Copied %d Zwift log/config files' % len(copied))
    return copied


def scan_zwift_log_for_urls(outdir):
    """Pull URLs/hostnames out of the copied Zwift logs (Zwift logs many of them)."""
    found = collections.Counter()
    hosts = collections.Counter()
    url_re = re.compile(r'https?://[^\s"\'<>\]\)]+')
    for p in glob.glob(os.path.join(outdir, 'zwift_logs', '*')):
        try:
            with open(p, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    for m in url_re.findall(line):
                        m = m.rstrip('.,;')
                        found[m.split('?')[0][:300]] += 1
                        try:
                            hosts[m.split('/')[2].lower()] += 1
                        except IndexError:
                            pass
        except Exception:
            continue
    return {'urls': found.most_common(500), 'hosts': hosts.most_common(200)}


def analyse_captures(pcaps, local_ips, proc_conns, dns_client_cache, log):
    ana = CaptureAnalysis(local_ips)
    for pcap in pcaps:
        log('Parsing %s ...' % os.path.basename(pcap))
        n = 0
        for ts, lt, data in iter_packets(pcap):
            ana.feed(ts, lt, data)
            n += 1
            if n % 200000 == 0:
                log('  %d packets ...' % n)
    log('Parsed %d packets (%s payload volume, %d unparsed)' % (ana.packets, human(ana.bytes_total), ana.unparsed))
    hosts = ana.summarize(proc_conns=proc_conns, dns_client_cache=dns_client_cache, log=log)
    flows = []
    for fl in ana.flows.values():
        d = dict(fl)
        d['http_content_types'] = sorted(d.get('http_content_types', set()))
        flows.append(d)
    flows.sort(key=lambda f: -(f['bytes_in'] + f['bytes_out']))
    cap = {
        'packets': ana.packets, 'bytes_total': ana.bytes_total, 'unparsed': ana.unparsed,
        'first_ts': ana.first_ts, 'last_ts': ana.last_ts,
        'dns_queries': dict(ana.dns_queries),
        'dns_answers': ana.dns_answers[:20000],
        'cnames': ana.cnames,
        'sni': {'%s:%s' % k: dict(v) for k, v in ana.sni.items()},
        'http_requests': ana.http_requests,
        'quic_endpoints': ['%s:%s' % q for q in sorted(ana.quic_flows)],
    }
    return cap, hosts, flows


def local_ip_list():
    ips = set()
    if psutil:
        try:
            for addrs in psutil.net_if_addrs().values():
                for a in addrs:
                    if a.family in (socket.AF_INET, socket.AF_INET6):
                        ips.add(a.address.split('%')[0])
        except Exception:
            pass
    return ips


def make_zip(outdir, include_pcap, log):
    zpath = outdir.rstrip('\\/') + '.zip'
    with zipfile.ZipFile(zpath, 'w', zipfile.ZIP_DEFLATED, allowZip64=True) as z:
        for root, _, files in os.walk(outdir):
            for f in files:
                if not include_pcap and f.lower().endswith(('.pcapng', '.pcap', '.etl')):
                    continue
                p = os.path.join(root, f)
                z.write(p, os.path.relpath(p, os.path.dirname(outdir)))
    log('Zip written: %s (%s)' % (zpath, human(os.path.getsize(zpath))))
    return zpath


def wait_for_enter(prompt, duration=None, stop_flag=None):
    """Wait for Enter or until duration seconds passed."""
    if duration:
        print(prompt + '  (auto-stop in %d s, or press Enter)' % duration, flush=True)
    else:
        print(prompt, flush=True)
    done = threading.Event()

    def reader():
        try:
            sys.stdin.readline()
        except Exception:
            pass
        done.set()

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    start = time.time()
    while not done.is_set():
        if duration and time.time() - start >= duration:
            break
        done.wait(0.5)
    return time.time() - start


def default_outdir():
    base = os.path.join(os.path.expanduser('~'), 'Desktop')
    if not os.path.isdir(base):
        base = os.getcwd()
    return os.path.join(base, 'ZwiftVideoMonitor_' + dt.datetime.now().strftime('%Y%m%d_%H%M%S'))


def monitor(args):
    outdir = args.output or default_outdir()
    os.makedirs(outdir, exist_ok=True)
    log = Log(os.path.join(outdir, 'monitor.log'))
    log('Zwift Video Monitor %s - output folder: %s' % (VERSION, outdir))
    if psutil is None:
        log('WARNING: psutil missing, process monitoring disabled')
    if not is_admin():
        log('WARNING: not running as administrator -> no packet capture (DNS/SNI/volume per host).')
        log('         Right-click the exe and choose "Run as administrator" for full results.')
    ctx = {'tool_version': VERSION}
    dirs, docs = zwift_dirs()
    ctx['system_info'] = collect_system_info(log, dirs, docs)
    write_json(os.path.join(outdir, 'system_info.json'), ctx['system_info'])

    print('')
    print('=' * 70)
    print('  1. Make sure Zwift is installed (it may already be running).')
    print('  2. Press Enter here to START monitoring.')
    print('  3. Log in, pick a Zwift VIDEO route and ride 5-10 minutes.')
    print('     If possible, also open/close the video quality setting in Zwift.')
    print('  4. Come back here and press Enter to STOP.')
    print('=' * 70)
    if not args.yes:
        wait_for_enter('Press Enter to start ...')

    log('Taking file snapshot of Zwift folders (this can take a while) ...')
    snap_before = snapshot_dirs(dirs, log)
    disk_before = {}
    for d in dirs:
        try:
            disk_before[d] = shutil.disk_usage(d).free
        except OSError:
            pass

    pm = ProcessMonitor(log) if psutil else None
    if pm:
        pm.start()
    pk = Pktmon(log, outdir, pkt_size=args.pkt_size, file_size_mb=args.file_size)
    cap_ok = pk.start()
    ctx['pktmon'] = pk.info
    net0 = psutil.net_io_counters() if psutil else None
    io0 = {}
    ctx['started'] = now_iso()
    t_start = time.time()
    log('MONITORING. Ride your Zwift Video route now.')
    elapsed = wait_for_enter('Press Enter to STOP monitoring ...', duration=args.duration)
    ctx['stopped'] = now_iso()
    ctx['duration_s'] = int(elapsed)
    log('Stopping ...')
    pcaps = pk.stop()
    if pm:
        pm.stop()
        pm.join(timeout=15)
    net1 = psutil.net_io_counters() if psutil else None
    if net0 and net1:
        ctx['net_delta'] = {'recv': net1.bytes_recv - net0.bytes_recv, 'sent': net1.bytes_sent - net0.bytes_sent}

    log('Taking second file snapshot ...')
    snap_after = snapshot_dirs(dirs, log)
    ctx['file_changes'] = diff_snapshots(snap_before, snap_after)
    ctx['disk_free_delta'] = {}
    for d, free in disk_before.items():
        try:
            ctx['disk_free_delta'][d] = shutil.disk_usage(d).free - free
        except OSError:
            pass
    write_csv(os.path.join(outdir, 'file_changes.csv'), ctx['file_changes'],
              ['change', 'delta', 'size', 'mtime', 'path'])

    pdata = pm.export() if pm else {}
    ctx['process_data'] = pdata
    # disk io delta per process from samples
    io_delta = {}
    if pdata.get('samples'):
        first, last = {}, {}
        for s in pdata['samples']:
            for pid, v in s['procs'].items():
                first.setdefault(pid, v)
                last[pid] = v
        for pid, v in last.items():
            f = first[pid]
            io_delta[v['name'] + '(%s)' % pid] = {'read': v['read_bytes'] - f['read_bytes'],
                                                  'write': v['write_bytes'] - f['write_bytes']}
    ctx['process_io_delta'] = io_delta
    write_json(os.path.join(outdir, 'process_data.json'), pdata)
    write_csv(os.path.join(outdir, 'connections.csv'), pdata.get('connections', []),
              ['process', 'pid', 'proto', 'laddr', 'lport', 'raddr', 'rport', 'statuses', 'first_seen', 'last_seen'])
    write_csv(os.path.join(outdir, 'open_files.csv'), pdata.get('open_files', []),
              ['process', 'pid', 'path', 'count', 'first_seen', 'last_seen'])

    copy_zwift_logs(dirs, docs, outdir, log)
    ctx['zwift_log_urls'] = scan_zwift_log_for_urls(outdir)
    write_json(os.path.join(outdir, 'zwift_log_urls.json'), ctx['zwift_log_urls'])

    ctx['capture'] = {'packets': 0, 'reason': 'no pktmon capture' if not cap_ok else 'conversion failed'}
    ctx['hosts'] = []
    if pcaps:
        try:
            cap, hosts, flows = analyse_captures(pcaps, local_ip_list(), pdata.get('connections'),
                                                 pdata.get('dns_client_cache'), log)
            ctx['capture'] = cap
            ctx['hosts'] = hosts
            write_json(os.path.join(outdir, 'capture_analysis.json'), cap)
            write_json(os.path.join(outdir, 'hosts.json'), hosts)
            write_csv(os.path.join(outdir, 'hosts.csv'), hosts,
                      ['label', 'ip', 'class', 'bytes_in', 'bytes_out', 'flows', 'quic', 'processes', 'ports', 'names', 'rdns'])
            write_csv(os.path.join(outdir, 'flows.csv'), flows,
                      ['proto', 'raddr', 'rport', 'lport', 'process', 'bytes_in', 'bytes_out', 'pkts_in', 'pkts_out',
                       'sni', 'http_host', 'names', 'http_content_types', 'first_ts', 'last_ts'])
        except Exception as e:
            log('Capture analysis failed: %r' % e)
            ctx['capture'] = {'packets': 0, 'reason': 'analysis failed: %r' % e}
            with open(os.path.join(outdir, 'analysis_error.txt'), 'w') as f:
                f.write(traceback.format_exc())

    report = build_text_report(ctx)
    with open(os.path.join(outdir, 'REPORT.txt'), 'w', encoding='utf-8') as f:
        f.write(report)
    ctx_small = {k: v for k, v in ctx.items() if k not in ('process_data',)}
    ctx_small['capture'] = {k: v for k, v in ctx.get('capture', {}).items()
                            if k not in ('dns_answers', 'http_requests')}
    write_json(os.path.join(outdir, 'summary.json'), ctx_small)
    print('')
    print(report)
    print('')
    log.close()
    zpath = make_zip(outdir, include_pcap=not args.no_pcap, log=Log())
    print('')
    print('DONE. Send this file for analysis:')
    print('   ' + zpath)
    print('(The folder next to it contains the same data unzipped. The .pcapng holds the')
    print(' first %d bytes of every packet; TLS payloads are encrypted, but the Zwift logs' % args.pkt_size)
    print(' may contain your player id. Review before sharing if that matters to you.)')
    if not args.yes:
        wait_for_enter('Press Enter to exit.')


def parse_only(args):
    log = Log()
    pcaps = []
    for p in args.parse:
        pcaps += glob.glob(p) or [p]
    conns = None
    dns_cache = None
    if args.process_data and os.path.isfile(args.process_data):
        with open(args.process_data, encoding='utf-8') as f:
            pd = json.load(f)
        conns = pd.get('connections')
        dns_cache = pd.get('dns_client_cache')
    local_ips = set(args.local_ip or []) | local_ip_list()
    cap, hosts, flows = analyse_captures(pcaps, local_ips, conns, dns_cache, log)
    ctx = {'capture': cap, 'hosts': hosts, 'process_data': {'connections': conns or []},
           'file_changes': [], 'system_info': {}}
    outdir = args.output or os.path.dirname(os.path.abspath(pcaps[0]))
    os.makedirs(outdir, exist_ok=True)
    write_json(os.path.join(outdir, 'hosts.json'), hosts)
    write_csv(os.path.join(outdir, 'hosts.csv'), hosts,
              ['label', 'ip', 'class', 'bytes_in', 'bytes_out', 'flows', 'quic', 'processes', 'ports', 'names', 'rdns'])
    write_csv(os.path.join(outdir, 'flows.csv'), flows,
              ['proto', 'raddr', 'rport', 'lport', 'process', 'bytes_in', 'bytes_out', 'pkts_in', 'pkts_out',
               'sni', 'http_host', 'names', 'http_content_types', 'first_ts', 'last_ts'])
    write_json(os.path.join(outdir, 'capture_analysis.json'), cap)
    print(build_text_report(ctx))


def main(argv=None):
    ap = argparse.ArgumentParser(description='Monitor a Zwift (Video) ride: network, processes, files.')
    ap.add_argument('--duration', type=int, default=None, help='stop automatically after N seconds')
    ap.add_argument('--output', help='output folder (default: Desktop\\ZwiftVideoMonitor_<timestamp>)')
    ap.add_argument('--pkt-size', type=int, default=700, help='bytes captured per packet (default 700, 0 = full)')
    ap.add_argument('--file-size', type=int, default=1024, help='pktmon file size in MB per file (default 1024)')
    ap.add_argument('--no-pcap', action='store_true', help='do not include the .pcapng in the zip')
    ap.add_argument('--yes', '-y', action='store_true', help='no interactive prompts (use with --duration)')
    ap.add_argument('--parse', nargs='+', help='only analyse existing .pcap/.pcapng file(s)')
    ap.add_argument('--process-data', help='process_data.json to combine with --parse')
    ap.add_argument('--local-ip', nargs='*', help='local IP(s) of the captured machine (for --parse)')
    args = ap.parse_args(argv)
    try:
        if args.parse:
            parse_only(args)
        else:
            monitor(args)
    except KeyboardInterrupt:
        print('\nInterrupted.')
        if IS_WINDOWS:
            run_cmd(['pktmon', 'stop'])
    except Exception:
        traceback.print_exc()
        if IS_WINDOWS:
            run_cmd(['pktmon', 'stop'])
        if not getattr(args, 'yes', False):
            wait_for_enter('An error occurred (see above). Press Enter to exit.')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
