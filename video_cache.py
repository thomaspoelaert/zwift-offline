"""
Zwift Video Caching Proxy

Intercepts and caches video streaming content from Zwift Video CDN servers.
Supports HLS (.m3u8 + .ts) and DASH (.mpd + .m4s) adaptive bitrate streaming.

After first download, video segments are served from local disk cache,
eliminating repeated data usage for previously ridden routes.

Configuration (in storage/):
    video-cache.txt         — Create this file to enable the video cache.
    video_cache_domains.txt — One CDN domain per line to intercept.
    video_cache_config.json — Optional settings (max_size_gb, quality, etc).

The cache stores segments in storage/video_cache/ organized by domain and path.
"""

import hashlib
import json
import os
import shutil
import sqlite3
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse

from urllib3 import PoolManager
from urllib3.util.ssl_ import create_urllib3_context


CACHE_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache_entries (
    url_hash TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    path TEXT NOT NULL,
    content_type TEXT,
    content_length INTEGER,
    cache_file TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_accessed TEXT NOT NULL,
    access_count INTEGER DEFAULT 1,
    is_manifest INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_domain ON cache_entries(domain);
CREATE INDEX IF NOT EXISTS idx_last_accessed ON cache_entries(last_accessed);
CREATE INDEX IF NOT EXISTS idx_is_manifest ON cache_entries(is_manifest);
"""


class VideoCacheConfig:
    def __init__(self, storage_dir):
        self.storage_dir = storage_dir
        self.enabled = os.path.isfile(os.path.join(storage_dir, 'video-cache.txt'))
        self.cache_dir = os.path.join(storage_dir, 'video_cache')
        self.db_path = os.path.join(self.cache_dir, 'cache.db')
        self.max_size_gb = 50
        self.max_quality = None  # None = don't restrict
        self.passthrough_manifests = False  # Always fetch fresh manifests
        self.domains = []
        self._load_domains()
        self._load_config()

    def _load_domains(self):
        path = os.path.join(self.storage_dir, 'video_cache_domains.txt')
        if os.path.isfile(path):
            with open(path) as f:
                self.domains = [
                    line.strip() for line in f
                    if line.strip() and not line.startswith('#')
                ]

    def _load_config(self):
        path = os.path.join(self.storage_dir, 'video_cache_config.json')
        if os.path.isfile(path):
            try:
                with open(path) as f:
                    cfg = json.load(f)
                self.max_size_gb = cfg.get('max_size_gb', self.max_size_gb)
                self.max_quality = cfg.get('max_quality', self.max_quality)
                self.passthrough_manifests = cfg.get(
                    'passthrough_manifests', self.passthrough_manifests
                )
            except (json.JSONDecodeError, IOError) as e:
                print(f'[VideoCache] Error loading config: {e}')


class VideoCacheDB:
    def __init__(self, db_path):
        self.db_path = db_path
        self.local = threading.local()
        self._init_db()

    def _get_conn(self):
        if not hasattr(self.local, 'conn') or self.local.conn is None:
            self.local.conn = sqlite3.connect(self.db_path)
            self.local.conn.row_factory = sqlite3.Row
        return self.local.conn

    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.executescript(CACHE_SCHEMA)
        conn.close()

    def get(self, url_hash):
        conn = self._get_conn()
        row = conn.execute(
            'SELECT * FROM cache_entries WHERE url_hash = ?', (url_hash,)
        ).fetchone()
        if row:
            conn.execute(
                'UPDATE cache_entries SET last_accessed = ?, access_count = access_count + 1 '
                'WHERE url_hash = ?',
                (datetime.now().isoformat(), url_hash)
            )
            conn.commit()
        return row

    def put(self, url_hash, url, domain, path, content_type, content_length,
            cache_file, is_manifest=False):
        conn = self._get_conn()
        now = datetime.now().isoformat()
        conn.execute(
            'INSERT OR REPLACE INTO cache_entries '
            '(url_hash, url, domain, path, content_type, content_length, '
            ' cache_file, created_at, last_accessed, access_count, is_manifest) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)',
            (url_hash, url, domain, path, content_type, content_length,
             cache_file, now, now, 1 if is_manifest else 0)
        )
        conn.commit()

    def get_total_size(self):
        conn = self._get_conn()
        row = conn.execute(
            'SELECT COALESCE(SUM(content_length), 0) as total FROM cache_entries'
        ).fetchone()
        return row['total'] if row else 0

    def get_lru_entries(self, limit=100):
        conn = self._get_conn()
        return conn.execute(
            'SELECT * FROM cache_entries WHERE is_manifest = 0 '
            'ORDER BY last_accessed ASC LIMIT ?',
            (limit,)
        ).fetchall()

    def delete(self, url_hash):
        conn = self._get_conn()
        conn.execute('DELETE FROM cache_entries WHERE url_hash = ?', (url_hash,))
        conn.commit()

    def get_stats(self):
        conn = self._get_conn()
        stats = {}
        row = conn.execute(
            'SELECT COUNT(*) as count, COALESCE(SUM(content_length), 0) as size, '
            'COALESCE(SUM(access_count), 0) as hits FROM cache_entries'
        ).fetchone()
        stats['total_entries'] = row['count']
        stats['total_size_bytes'] = row['size']
        stats['total_size_gb'] = round(row['size'] / (1024**3), 2)
        stats['total_hits'] = row['hits']
        row = conn.execute(
            'SELECT COUNT(*) as count FROM cache_entries WHERE is_manifest = 1'
        ).fetchone()
        stats['manifest_count'] = row['count']
        row = conn.execute(
            'SELECT domain, COUNT(*) as count, SUM(content_length) as size '
            'FROM cache_entries GROUP BY domain ORDER BY size DESC'
        ).fetchall()
        stats['by_domain'] = [
            {'domain': r['domain'], 'entries': r['count'],
             'size_mb': round((r['size'] or 0) / (1024**2), 1)}
            for r in row
        ]
        return stats


class VideoCache:
    def __init__(self, config):
        self.config = config
        self.db = VideoCacheDB(config.db_path)
        self.pool = PoolManager(num_pools=10, maxsize=10, retries=2, timeout=30.0)
        self._eviction_lock = threading.Lock()
        os.makedirs(config.cache_dir, exist_ok=True)
        size = self.db.get_total_size()
        print(f'[VideoCache] Initialized: {size / (1024**3):.2f} GB cached, '
              f'max {config.max_size_gb} GB')

    def _url_hash(self, url):
        return hashlib.sha256(url.encode()).hexdigest()

    def _cache_file_path(self, url_hash, domain):
        domain_dir = os.path.join(self.config.cache_dir, domain.replace('.', '_'))
        os.makedirs(domain_dir, exist_ok=True)
        return os.path.join(domain_dir, url_hash)

    def _is_manifest(self, path):
        lower = path.lower()
        return lower.endswith('.m3u8') or lower.endswith('.mpd')

    def _is_video_segment(self, path):
        lower = path.lower()
        return (lower.endswith('.ts') or lower.endswith('.m4s') or
                lower.endswith('.mp4') or lower.endswith('.fmp4') or
                lower.endswith('.cmfv') or lower.endswith('.cmfa'))

    def _should_rewrite_manifest(self, content, content_type):
        """Check if we should rewrite an HLS manifest to limit quality."""
        if not self.config.max_quality:
            return False
        if not content_type:
            return False
        return ('mpegurl' in content_type.lower() or
                'application/vnd.apple' in content_type.lower())

    def _rewrite_hls_manifest(self, content, max_bandwidth):
        """
        Rewrite an HLS master playlist to remove quality levels above max_bandwidth.
        This reduces data usage by limiting the maximum quality Zwift can request.

        max_bandwidth is in bits/sec. Approximate values:
            720p:  ~3_000_000  (3 Mbps, ~1.35 GB/hr)
            1080p: ~8_000_000  (8 Mbps, ~3.6 GB/hr)
            1440p: ~16_000_000 (16 Mbps, ~7.2 GB/hr)
            4K:    ~40_000_000 (40 Mbps, ~18 GB/hr)
        """
        lines = content.decode('utf-8', errors='replace').splitlines()
        filtered = []
        skip_next = False
        for line in lines:
            if skip_next:
                skip_next = False
                continue
            if line.startswith('#EXT-X-STREAM-INF:'):
                bw_match = None
                for part in line.split(','):
                    if 'BANDWIDTH=' in part:
                        try:
                            bw_match = int(part.split('BANDWIDTH=')[1].split(',')[0])
                        except (ValueError, IndexError):
                            pass
                if bw_match and bw_match > max_bandwidth:
                    skip_next = True
                    continue
            filtered.append(line)
        return '\n'.join(filtered).encode('utf-8')

    def fetch_and_cache(self, domain, path, headers=None):
        """
        Fetch content from the origin CDN, cache it, and return (data, content_type, status).
        If already cached, return from cache.
        """
        url = f'https://{domain}{path}'
        url_hash = self._url_hash(url)
        is_manifest = self._is_manifest(path)

        # Manifests: optionally always fetch fresh (they change for live/adaptive)
        if not is_manifest or not self.config.passthrough_manifests:
            cached = self.db.get(url_hash)
            if cached:
                cache_file = cached['cache_file']
                if os.path.isfile(cache_file):
                    with open(cache_file, 'rb') as f:
                        data = f.read()
                    return data, cached['content_type'], 200

        # Fetch from origin
        try:
            req_headers = {}
            if headers:
                for h in ['User-Agent', 'Accept', 'Accept-Encoding', 'Range',
                           'Accept-Language', 'Referer', 'Origin']:
                    if h in headers:
                        req_headers[h] = headers[h]

            response = self.pool.request(
                'GET', url, headers=req_headers, preload_content=True
            )
            data = response.data
            content_type = response.headers.get('Content-Type', '')
            status = response.status

            if status != 200:
                return data, content_type, status

            # Quality limiting for HLS master playlists
            if (is_manifest and self.config.max_quality and
                    self._should_rewrite_manifest(data, content_type)):
                quality_map = {
                    '720p': 3_000_000,
                    '1080p': 8_000_000,
                    '1440p': 16_000_000,
                    '4k': 40_000_000,
                }
                max_bw = quality_map.get(
                    self.config.max_quality.lower(), 40_000_000
                )
                data = self._rewrite_hls_manifest(data, max_bw)

            # Store in cache
            cache_file = self._cache_file_path(url_hash, domain)
            with open(cache_file, 'wb') as f:
                f.write(data)

            self.db.put(
                url_hash=url_hash,
                url=url,
                domain=domain,
                path=path,
                content_type=content_type,
                content_length=len(data),
                cache_file=cache_file,
                is_manifest=is_manifest,
            )

            # Check if eviction needed (in background)
            threading.Thread(target=self._maybe_evict, daemon=True).start()

            return data, content_type, status

        except Exception as e:
            print(f'[VideoCache] Fetch error for {url}: {e}')
            return None, None, 502

    def _maybe_evict(self):
        if not self._eviction_lock.acquire(blocking=False):
            return
        try:
            max_bytes = self.config.max_size_gb * (1024**3)
            total = self.db.get_total_size()
            if total <= max_bytes:
                return

            target = int(max_bytes * 0.9)
            print(f'[VideoCache] Evicting: {total/(1024**3):.2f} GB > '
                  f'{self.config.max_size_gb} GB limit, target {target/(1024**3):.2f} GB')

            while total > target:
                entries = self.db.get_lru_entries(50)
                if not entries:
                    break
                for entry in entries:
                    try:
                        if os.path.isfile(entry['cache_file']):
                            os.remove(entry['cache_file'])
                    except OSError:
                        pass
                    self.db.delete(entry['url_hash'])
                    total -= entry['content_length'] or 0
                    if total <= target:
                        break

            print(f'[VideoCache] After eviction: {total/(1024**3):.2f} GB')
        finally:
            self._eviction_lock.release()

    def get_stats(self):
        return self.db.get_stats()

    def clear(self):
        if os.path.isdir(self.config.cache_dir):
            shutil.rmtree(self.config.cache_dir)
        os.makedirs(self.config.cache_dir, exist_ok=True)
        self.db = VideoCacheDB(self.config.db_path)
        print('[VideoCache] Cache cleared')


class VideoCacheHandler(BaseHTTPRequestHandler):
    """HTTP(S) handler that serves cached video content or proxies to origin."""

    video_cache = None  # Set by standalone.py

    def log_message(self, format, *args):
        pass  # Suppress default logging

    def do_GET(self):
        if self.path == '/video_cache/stats':
            self._serve_stats()
            return
        if self.path == '/video_cache/clear' and self.command == 'GET':
            self._serve_clear_confirm()
            return

        # Determine origin domain from Host header or path
        host = self.headers.get('Host', '')
        domain = host.split(':')[0] if host else None

        if not domain or not self.video_cache:
            self.send_error(404)
            return

        data, content_type, status = self.video_cache.fetch_and_cache(
            domain, self.path, headers=self.headers
        )

        if data is None:
            self.send_error(status or 502)
            return

        self.send_response(status)
        if content_type:
            self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', len(data))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(data)

    def do_HEAD(self):
        self.do_GET()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()

    def _serve_stats(self):
        stats = self.video_cache.get_stats()
        data = json.dumps(stats, indent=2).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(data))
        self.end_headers()
        self.wfile.write(data)

    def _serve_clear_confirm(self):
        html = (
            '<html><body><h2>Video Cache</h2>'
            '<p>Are you sure you want to clear the video cache?</p>'
            '<form method="POST" action="/video_cache/clear">'
            '<button type="submit">Clear Cache</button></form>'
            '</body></html>'
        ).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', len(html))
        self.end_headers()
        self.wfile.write(html)

    def do_POST(self):
        if self.path == '/video_cache/clear' and self.video_cache:
            self.video_cache.clear()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Cache cleared')
        else:
            self.send_error(404)
