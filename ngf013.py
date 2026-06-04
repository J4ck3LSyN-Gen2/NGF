#!/usr/bin/env python3
import asyncio, argparse, json, logging, os, random, re, sys, signal, time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

import aiosqlite
from curl_cffi import requests
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn, TimeElapsedColumn
from rich.logging import RichHandler
from rich.table import Table

__version__ = "0.1.3"
__author__ = "J4ck3LSyN (Improved by Grok)"
__license__ = "MIT"

# ===================== CONFIG =====================
DEFAULT_TIMEOUT = 10
DEFAULT_MAX_LATENCY = 8.0
DEFAULT_CONCURRENCY = 40
MAX_PROXIES = 250
MAX_RETRIES = 2
SHUTDOWN_TIMEOUT = 15  # Seconds to wait for active tasks before forcing exit
DB_PATH = "ngf_state.db"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
]

TEST_TARGETS = [
    "http://ip-api.com/json?fields=status,message,countryCode,city,isp,org,as,query",
    "https://api.ipify.org?format=json",
    "https://ifconfig.co/json",
    "https://ipinfo.io/json",
]

PROXY_SOURCES = {
    "socks5": [
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/proxyscrape/free-proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
        "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/SOCKS5_RAW.txt"
    ],
    "socks4": [
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
        "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/SOCKS4_RAW.txt"
    ],
    "http": [
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies.txt",
    ],
    "https": [
        "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/refs/heads/master/https.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt",
        "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/HTTPS_RAW.txt"
    ]
}

# ==================== LOGGING =====================
logger = logging.getLogger("NGF")
logger.setLevel(logging.INFO)

# Shared console instance to synchronize logs and progress bars
CONSOLE = Console()
rich_handler = RichHandler(console=CONSOLE, show_path=False, omit_repeated_times=False)
logger.addHandler(rich_handler)

# ==================== CORE CLASSES ====================
class Proxy:
    """
    Represents a single proxy server and its associated metadata.
    
    Attributes:
        proto: Protocol (http, https, socks4, socks5).
        ip: IPv4 address.
        port: Port number.
        anonymity: Detection level (Elite, Anonymous, Transparent).
        dns_leak: Boolean indicating if the DNS resolver matches the host country instead of the proxy.
        latency: Response time in seconds for the target check.
    """
    def __init__(self, proto: str, ip: str, port: int, found_via: str = "LOCAL"):
        self.proto = proto
        self.ip = ip
        self.port = port
        self.found_via = found_via
        self.working = False
        self.latency: Optional[float] = None
        self.anonymity = "Unknown"
        self.country = "??"
        self.city = "Unknown"
        self.isp = "Unknown"
        self.org = "Unknown"
        self.asn = "Unknown"
        self.dns_leak = False
        self.verified = False
        self.checked_at: Optional[str] = None

    def to_url(self) -> str:
        """Converts proxy info to a URI string. Uses socks5h for remote DNS resolution."""
        prefix = "socks5h" if self.proto == "socks5" else self.proto
        return f"{prefix}://{self.ip}:{self.port}"

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}


class ProxyDB:
    """Handles persistence of proxy metadata using an optimized SQLite backend."""
    def __init__(self, path: str = DB_PATH):
        self.path = path
        self.db: Optional[aiosqlite.Connection] = None
        self._lock = asyncio.Lock()

    async def init(self):
        """Initializes the database schema and sets performance PRAGMAs."""
        db_path = Path(self.path).resolve()
        logger.debug(f"Initializing database at {db_path}")

        # Verify write permissions for the database directory
        if not os.access(db_path.parent, os.W_OK):
            logger.critical(f"Permission denied: Directory '{db_path.parent}' is not writable. Database cannot be initialized.")
            sys.exit(1)

        try:
            self.db = await aiosqlite.connect(str(db_path))
        except Exception as e:
            logger.critical(f"Fatal error: Unable to open database file at {db_path}: {e}")
            sys.exit(1)

        # Stability PRAGMAs should be set BEFORE the first write attempt.
        # This helps avoid 'disk I/O error' on filesystems with locking issues (WSL/NFS).
        try:
            await self.db.execute("PRAGMA busy_timeout = 5000")
            await self.db.execute("PRAGMA synchronous = NORMAL")
            await self.db.execute("PRAGMA temp_store = MEMORY")
        except Exception: pass

        try:
            await self.db.execute("""
                CREATE TABLE IF NOT EXISTS proxies (
                    ip TEXT PRIMARY KEY,
                    proto TEXT,
                    port INTEGER,
                    working INTEGER,
                    latency REAL,
                    anonymity TEXT,
                    country TEXT,
                    city TEXT,
                    isp TEXT,
                    org TEXT,
                    asn TEXT,
                    dns_leak INTEGER,
                    verified INTEGER,
                    checked_at TEXT,
                    found_via TEXT
                )
            """)
        except Exception as e:
            if "disk I/O error" in str(e).lower():
                logger.warning("Disk I/O error detected. Falling back to MEMORY journaling.")
                await self.db.execute("PRAGMA journal_mode = MEMORY")
                # Re-try the table creation now that disk journaling is bypassed
                await self.db.execute("CREATE TABLE IF NOT EXISTS proxies (ip TEXT PRIMARY KEY, proto TEXT, port INTEGER, working INTEGER, latency REAL, anonymity TEXT, country TEXT, city TEXT, isp TEXT, org TEXT, asn TEXT, dns_leak INTEGER, verified INTEGER, checked_at TEXT, found_via TEXT)")
            else: raise

        # Attempt to enable high-concurrency optimizations.
        try:
            await self.db.execute("PRAGMA journal_mode=WAL")
            await self.db.execute("PRAGMA cache_size=-64000")
        except Exception:
            logger.debug("WAL mode not supported on this filesystem.")

        await self.db.execute("CREATE INDEX IF NOT EXISTS idx_working ON proxies(working)")
        await self.db.execute("CREATE INDEX IF NOT EXISTS idx_country ON proxies(country)")
        await self.db.execute("CREATE INDEX IF NOT EXISTS idx_latency ON proxies(latency)")
        await self.db.execute("CREATE INDEX IF NOT EXISTS idx_anonymity ON proxies(anonymity)")
        await self.db.execute("CREATE INDEX IF NOT EXISTS idx_proto ON proxies(proto)")
        await self.db.execute("CREATE INDEX IF NOT EXISTS idx_checked_at ON proxies(checked_at)")
        await self.db.commit()

    async def close(self):
        if self.db:
            await self.db.close()

    async def is_dead(self, ip: str) -> bool:
        """Verify if an IP is in the database and marked as non-working."""
        logger.debug(f"Verifying if {ip} is dead in database")
        async with self._lock:
            async with self.db.execute("SELECT 1 FROM proxies WHERE ip = ? AND working = 0", (ip,)) as cursor:
                return await cursor.fetchone() is not None

    async def get_dead_ips(self, ips: List[str]) -> Set[str]:
        """Returns a set of IPs from the list that are already marked as dead in the DB."""
        if not ips: return set()
        dead = set()
        async with self._lock:
            for i in range(0, len(ips), 900):
                chunk = ips[i:i+900]
                placeholders = ','.join(['?'] * len(chunk))
                query = f"SELECT ip FROM proxies WHERE ip IN ({placeholders}) AND working = 0"
                async with self.db.execute(query, chunk) as cursor:
                    rows = await cursor.fetchall()
                    for r in rows: dead.add(r[0])
        return dead

    async def upsert(self, p: Proxy):
        """Inserts or updates proxy records."""
        logger.debug(f"Upserting proxy metadata for {p.ip} (Working: {p.working})")
        async with self._lock:
            await self.db.execute("""
                INSERT OR REPLACE INTO proxies 
                (ip, proto, port, working, latency, anonymity, country, city, isp, org, asn, dns_leak, verified, checked_at, found_via)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                p.ip, p.proto, p.port, int(p.working), p.latency,
                p.anonymity, p.country, p.city, p.isp, p.org, p.asn,
                int(p.dns_leak) if p.dns_leak is not None else None,
                int(p.verified), p.checked_at, p.found_via
            ))
            await self.db.commit()

    async def batch_upsert(self, proxies: List[Proxy]):
        """High-performance bulk insert/update for discovery phases."""
        if not proxies: return
        async with self._lock:
            data = [
                (p.ip, p.proto, p.port, int(p.working), p.latency,
                 p.anonymity, p.country, p.city, p.isp, p.org, p.asn,
                 int(p.dns_leak) if p.dns_leak is not None else None,
                 int(p.verified), p.checked_at, p.found_via)
                for p in proxies
            ]
            await self.db.executemany("""
                INSERT OR IGNORE INTO proxies 
                (ip, proto, port, working, latency, anonymity, country, city, isp, org, asn, dns_leak, verified, checked_at, found_via)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, data)
            await self.db.commit()

    async def get_seeds(self, types: List[str]) -> List[Proxy]:
        """Fetches the most recently verified working proxies to use as potential pivots."""
        logger.debug(f"Retrieving working seeds from DB for types: {types}")
        async with self._lock:
            placeholders = ','.join(['?'] * len(types))
            query = f"""
                SELECT proto, ip, port FROM proxies 
                WHERE working = 1 AND proto IN ({placeholders})
                ORDER BY checked_at DESC LIMIT 150
            """
            async with self.db.execute(query, types) as cursor:
                rows = await cursor.fetchall()
                return [Proxy(r[0], r[1], r[2]) for r in rows]

    async def get_candidates(self, types: List[str]) -> List[Proxy]:
        """Fetches all candidates for re-validation from DB."""
        async with self._lock:
            placeholders = ','.join(['?'] * len(types))
            query = f"SELECT proto, ip, port, working, latency, anonymity, country, city, isp, org, asn, dns_leak, verified, checked_at, found_via FROM proxies WHERE proto IN ({placeholders})"
            async with self.db.execute(query, types) as cursor:
                rows = await cursor.fetchall()
                results = []
                for r in rows:
                    p = Proxy(r[0], r[1], r[2], found_via=r[14])
                    p.working = bool(r[3])
                    p.latency = r[4]
                    p.anonymity = r[5]
                    p.country = r[6]
                    p.city = r[7]
                    p.isp = r[8]
                    p.org = r[9]
                    p.asn = r[10]
                    p.dns_leak = bool(r[11]) if r[11] is not None else False
                    p.verified = bool(r[12])
                    p.checked_at = r[13]
                    results.append(p)
                return results

    async def get_stats(self) -> Dict[str, int]:
        """Returns summary statistics of the database content."""
        async with self._lock:
            async with self.db.execute("SELECT COUNT(*) FROM proxies") as cursor:
                total = (await cursor.fetchone())[0]
            async with self.db.execute("SELECT COUNT(*) FROM proxies WHERE working = 1") as cursor:
                working = (await cursor.fetchone())[0]
            async with self.db.execute("SELECT COUNT(*) FROM proxies WHERE working = 0 AND checked_at IS NOT NULL") as cursor:
                dead = (await cursor.fetchone())[0]
            async with self.db.execute("SELECT country, COUNT(*) FROM proxies GROUP BY country ORDER BY COUNT(*) DESC") as cursor:
                regions = await cursor.fetchall()
            return {"total": total, "working": working, "dead": dead, "regions": regions}


    async def query_proxies(self, ip: Optional[str] = None, country: Optional[str] = None, max_latency: Optional[float] = None,
                           proto: Optional[str] = None, anonymity: Optional[str] = None, source: Optional[str] = None) -> List[Proxy]:
        """Filters the database for specific metadata; used by the CLI dump/export tools."""
        async with self._lock:
            query = "SELECT proto, ip, port, working, latency, anonymity, country, city, isp, org, asn, dns_leak, verified, checked_at, found_via FROM proxies WHERE 1=1"
            params = []
            if ip:
                query += " AND ip = ?"
                params.append(ip)
            if country:
                query += " AND country = ?"
                params.append(country.upper())
            if proto:
                query += " AND proto = ?"
                params.append(proto.lower())
            if anonymity:
                query += " AND anonymity = ?"
                params.append(anonymity)
            if source:
                query += " AND found_via LIKE ?"
                params.append(f"%{source}%")
            if max_latency is not None:
                query += " AND latency <= ?"
                params.append(max_latency)
            
            async with self.db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                results = []
                for r in rows:
                    p = Proxy(r[0], r[1], r[2], found_via=r[14])
                    p.working, p.latency, p.anonymity, p.country, p.city, p.isp, p.org, p.asn = r[3:11]
                    p.working = bool(p.working)
                    p.dns_leak = bool(r[11]) if r[11] is not None else False
                    p.verified = bool(r[12])
                    p.checked_at = r[13]
                    results.append(p)
                return results

    async def clear(self):
        logger.debug(f"Clearing all entries from {self.path}")
        async with self._lock:
            await self.db.execute("DELETE FROM proxies")
            await self.db.execute("VACUUM")
            await self.db.commit()


class ProxyFetcher:
    """Main engine responsible for source fetching, pivot management, and concurrent validation."""
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.db = ProxyDB()
        self.console = CONSOLE
        
        self.harvester_session = requests.AsyncSession(impersonate="chrome110")
        self.validator_session = requests.AsyncSession(impersonate="chrome110")
        logger.debug("AsyncSessions initialized with Chrome 110 TLS impersonation")
        
        self.semaphore = asyncio.Semaphore(args.threads)
        self.api_semaphore = asyncio.Semaphore(8)
        self.pivot_lock = asyncio.Lock()
        
        self.stop_event = asyncio.Event()
        self.working: List[Proxy] = []
        self.pivot: Optional[Proxy] = None
        self.pivot_usage = 0
        self.real_ip = None
        self.real_country = None
        
        self.preferred = {c.strip().upper() for c in (self.args.country or "").split(",") if c.strip()}
        self.excluded = {c.strip().upper() for c in (self.args.exclude or "").split(",") if c.strip()}

    async def get_real_info(self):
        """Fetches the host's public IP and Country Code for anonymity and DNS leak verification."""
        try:
            async with self.api_semaphore:
                resp = await self.harvester_session.get(
                    "http://ip-api.com/json?fields=query,countryCode", 
                    timeout=12
                )
                data = resp.json()
                self.real_ip = data.get("query")
                self.real_country = data.get("countryCode")
                logger.info(f"Real Identity: {self.real_ip} | Country: {self.real_country}")
        except Exception as e:
            logger.warning(f"Failed to detect real IP: {e}")

    async def _set_pivot(self, proxy: Proxy):
        """Updates the current pivot proxy thread-safely."""
        async with self.pivot_lock:
            self.pivot = proxy
            self.pivot_usage = 0
            logger.info(f"Pivot established: {proxy.ip}")

    async def check_proxy(self, proxy: Proxy, use_pivot: bool = False) -> bool:
        """
        Validates a proxy by:
        1. Auditing its metadata via a pivot (if OpSec is enabled).
        2. Performing a direct connectivity and latency check against randomized targets.
        3. Performing a DNS leak check.
        """
        proxy_url = proxy.to_url()
        target = random.choice(TEST_TARGETS)
        logger.debug(f"Checking {proxy.ip}:{proxy.port} via {target}")
        
        # Audit via pivot if requested
        if use_pivot and self.pivot:
            async with self.pivot_lock:
                pivot_url = self.pivot.to_url() if self.pivot else None
            
            if pivot_url:
                logger.debug(f"Auditing {proxy.ip} metadata via pivot {self.pivot.ip}")
                audit_success = False
                for attempt in range(MAX_RETRIES + 1):
                    try:
                        async with self.api_semaphore:
                            audit_resp = await self.harvester_session.get(
                                f"http://ip-api.com/json/{proxy.ip}?fields=status,countryCode,city,isp,org,as",
                                proxy=pivot_url,
                                timeout=10
                            )
                            # Track usage for metadata audits
                            async with self.pivot_lock:
                                if self.pivot:
                                    self.pivot_usage += 1
                                    if self.args.pivot_limit and self.pivot_usage >= self.args.pivot_limit:
                                        logger.info(f"Pivot {self.pivot.ip} reached usage limit ({self.args.pivot_limit}). Rotating...")
                                        self.pivot = None

                            if audit_resp.status_code == 200:
                                if not audit_resp.content:
                                    raise ValueError("Empty reply from server")
                                try:
                                    data = audit_resp.json()
                                    proxy.country = data.get("countryCode", proxy.country)
                                    proxy.city = data.get("city", proxy.city)
                                    proxy.isp = data.get("isp", proxy.isp)
                                    proxy.org = data.get("org", proxy.org)
                                    proxy.asn = data.get("as", proxy.asn)
                                    audit_success = True
                                    break
                                except (json.JSONDecodeError, ValueError):
                                    raise ValueError("Invalid JSON response")
                            elif audit_resp.status_code == 429:
                                logger.debug(f"Audit API rate-limit hit via pivot {self.pivot.ip if self.pivot else '??'}")
                                break
                    except Exception as e:
                        err_s = str(e)
                        if attempt < MAX_RETRIES:
                            await asyncio.sleep(0.5 * (attempt + 1))
                            continue
                        
                        if "(28)" in err_s: logger.debug(f"Audit timeout for {proxy.ip} via pivot")
                        elif "(52)" in err_s: logger.debug(f"Pivot returned empty reply for audit")
                        else: logger.debug(f"Metadata audit failed for {proxy.ip} via pivot: {e}")
                
                if not audit_success and self.args.opsec:
                    return False

        # Main validation
        for attempt in range(MAX_RETRIES + 1):
            try:
                start = time.time()
                headers = {"User-Agent": random.choice(USER_AGENTS)}
                
                resp = await self.validator_session.get(
                    target,
                    proxy=proxy_url,
                    headers=headers,
                    timeout=self.args.timeout or DEFAULT_TIMEOUT
                )
                
                if resp.status_code == 200:
                    proxy.latency = round(time.time() - start, 2)
                    logger.debug(f"[{proxy.ip}] Success on {target} in {proxy.latency}s")
                    data = resp.json() if resp.content else {}
                    
                    observed_ip = data.get("query") or data.get("ip") or data.get("origin") or ""
                    
                    proxy.working = True
                    proxy.verified = True
                    proxy.checked_at = datetime.now(timezone.utc).isoformat()
                    proxy.country = data.get("countryCode") or proxy.country
                    proxy.isp = data.get("isp") or proxy.isp
                    proxy.org = data.get("org") or proxy.org
                    proxy.asn = data.get("as") or proxy.asn
                    
                    # Anonymity
                    if observed_ip == proxy.ip:
                        proxy.anonymity = "Elite"
                    elif self.real_ip and observed_ip != self.real_ip:
                        proxy.anonymity = "Anonymous"
                    else:
                        proxy.anonymity = "Transparent"
                    
                    # DNS Leak Check
                    try:
                        dns_resp = await self.validator_session.get(
                            "http://edns.ip-api.com/json", 
                            proxy=proxy_url, 
                            timeout=8
                        )
                        if dns_resp.status_code == 200:
                            dns_data = dns_resp.json()
                            dns_geo = dns_data.get("dns", {}).get("geo", "")
                            if self.real_country and proxy.country != "??":
                                proxy.dns_leak = (self.real_country in dns_geo and proxy.country != self.real_country)
                    except:
                        proxy.dns_leak = None
                    
                    await self.db.upsert(proxy)
                    return True
                    
            except Exception as e:
                err_str = str(e)
                if "(28)" in err_str or "timeout" in err_str.lower():
                    logger.debug(f"Proxy {proxy.ip} validation error (attempt {attempt}): (curl timeout)")
                elif "(60)" in err_str:
                    logger.debug(f"Proxy {proxy.ip} validation error (attempt {attempt}): (SSL cert problem)")
                elif "(97)" in err_str:
                    logger.debug(f"Proxy {proxy.ip} validation error (attempt {attempt}): (SOCKS/Reset issue)")
                elif "(7)" in err_str:
                    logger.debug(f"Proxy {proxy.ip} validation error (attempt {attempt}): (Connection failed)")
                else:
                    logger.debug(f"Proxy {proxy.ip} validation error (attempt {attempt}): {e}")
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(0.5 * (attempt + 1))
        
        return False

    async def fetch_sources(self, urls: List[str], use_pivot: bool = False) -> List[Proxy]:
        """Fetches raw proxy lists from URLs and extracts IP:Port patterns."""
        fetch_proxy = self.pivot.to_url() if use_pivot and self.pivot else None
        pattern = re.compile(r'(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d):(\d{1,5})')
        
        async def fetch_one(url: str) -> List[Proxy]:
            found_in_source = []
            try:
                logger.debug(f"Fetching source list: {url}")
                resp = await self.harvester_session.get(url, proxy=fetch_proxy, timeout=25)
                if resp.status_code != 200:
                    return []
                
                # Track usage for source harvesting
                if use_pivot and fetch_proxy:
                    async with self.pivot_lock:
                        if self.pivot:
                            self.pivot_usage += 1
                            if self.args.pivot_limit and self.pivot_usage >= self.args.pivot_limit:
                                logger.info(f"Pivot {self.pivot.ip} reached usage limit during discovery. Rotating...")
                                self.pivot = None
                
                default_proto = "socks5" if "socks5" in url.lower() else "socks4" if "socks4" in url.lower() else "http"
                for match in pattern.finditer(resp.text):
                    ip, port = match.group(0).split(':')
                    port = int(port)
                    if 1 <= port <= 65535:
                        found_in_source.append(Proxy(default_proto, ip, port, found_via=url))
            except Exception as e:
                logger.debug(f"Source fetch failed {url}: {type(e).__name__}")
            return found_in_source

        results = await asyncio.gather(*(fetch_one(u) for u in urls))
        
        # Flatten and deduplicate candidates found in this discovery run
        unique_candidates = {}
        for sublist in results:
            for p in sublist:
                if p.ip not in unique_candidates:
                    unique_candidates[p.ip] = p
        
        if not unique_candidates:
            return []

        # Load all discovered candidates into the database completely first
        logger.debug(f"Batch inserting {len(unique_candidates)} unique candidates from sources")
        all_candidates = list(unique_candidates.values())
        await self.db.batch_upsert(all_candidates)

        # Return the discovered candidates; the worker threads handle filtering via --skip-dead
        return all_candidates

    async def _establish_pivot(self) -> bool:
        """
        Search for a stable pivot proxy.
        Order of operations:
        1. Manual entry via --pivot.
        2. Database seeds (known working from previous runs).
        3. Fresh bootstrap from a subset of sources.
        """
        logger.info("Phase 0: Establishing stealth pivot...")
        
        # Try manual pivots first if provided
        if self.args.pivot:
            manual_urls = [u.strip() for u in self.args.pivot.split(",") if u.strip()]
            logger.debug(f"Testing manual pivot candidates: {manual_urls}")
            for url in manual_urls:
                try:
                    # Simple parsing: proto://ip:port
                    proto, addr = url.split("://")
                    ip, port = addr.split(":")
                    p = Proxy(proto.lower(), ip, int(port), found_via="MANUAL_PIVOT")
                    if await self.check_proxy(p):
                        await self._set_pivot(p)
                        return True
                except Exception as e:
                    logger.warning(f"Failed to parse manual pivot '{url}': {e}")
        
        pivot_types = ["http", "https"] if self.args.pivot_http else self.args.type
        logger.debug(f"Searching for stable pivot proxy (Types: {pivot_types})")
        
        async def try_pivot(p: Proxy) -> bool:
            """Helper to validate and establish a pivot candidate."""
            if await self.check_proxy(p):
                await self._set_pivot(p)
                return True
            return False

        # Try DB seeds first
        seeds = await self.db.get_seeds(pivot_types)
        if seeds:
            logger.info(f"Prioritizing {len(seeds)} local DB seeds for rapid pivot recovery...")
            # Check seeds in parallel to find a working one as fast as possible
            seed_tasks = [asyncio.create_task(try_pivot(s)) for s in seeds[:40]]
            for future in asyncio.as_completed(seed_tasks):
                if await future:
                    for t in seed_tasks:
                        if not t.done(): t.cancel()
                    return True

        # Bootstrap from sources
        bootstrap_urls = []
        search_types = set(pivot_types)
        if "https" in search_types:
            search_types.add("http")
            
        for t in search_types:
            bootstrap_urls.extend(PROXY_SOURCES.get(t, [])[:3])

        candidates = await self.fetch_sources(bootstrap_urls)
        if candidates:
            logger.debug(f"Testing {len(candidates)} bootstrap candidates in parallel...")
            boot_tasks = [asyncio.create_task(try_pivot(p)) for p in candidates[:20]]
            for future in asyncio.as_completed(boot_tasks):
                if await future:
                    for t in boot_tasks:
                        if not t.done(): t.cancel()
                    return True

        logger.error("Failed to establish pivot.")
        return False

    async def _pivot_health_check(self):
        """Background task to ensure the pivot remains active; triggers recovery if it fails."""
        while not self.stop_event.is_set():
            if not self.pivot and (self.args.proxy_only or self.args.opsec):
                await self._establish_pivot()

            await asyncio.sleep(60)
            if self.pivot:
                if not await self.check_proxy(self.pivot):
                    logger.warning(f"Pivot {self.pivot.ip} died. Recovering...")
                    logger.debug(f"Pivot health check failed for {self.pivot.ip}")
                    async with self.pivot_lock:
                        self.pivot = None
                    if self.args.proxy_only or self.args.opsec:
                        await self._establish_pivot()

    async def run(self):
        """Primary execution flow: Init DB -> Pivot (Phase 0) -> Discover (Phase 1) -> Validate (Phase 2)."""
        await self.db.init()
        
        if self.args.proxy_only or self.args.opsec:
            if not await self._establish_pivot():
                logger.error("Could not establish pivot. Aborting.")
                return
            asyncio.create_task(self._pivot_health_check())
        else:
            await self.get_real_info()

        # Collect sources
        sources = []
        for t in self.args.type:
            sources.extend(PROXY_SOURCES.get(t, []))
            # Cross-pollinate HTTP and HTTPS sources as they are often mixed in public lists
            if t == "https":
                sources.extend(PROXY_SOURCES.get("http", []))
            elif t == "http":
                sources.extend(PROXY_SOURCES.get("https", []))

        # Deduplicate sources to avoid redundant network requests
        sources = list(dict.fromkeys(sources))

        if self.args.source:
            custom_sources = [s.strip() for s in self.args.source.split(",") if s.strip()]
            sources.extend(custom_sources)

        # Discovery phase
        if self.args.update_sources:
            logger.info(f" Refreshing candidates from {len(sources)} sources...")
            await self.fetch_sources(sources, use_pivot=self.args.opsec)
            logger.debug("")

        logger.info(" Loading candidates from database...")
        # Broaden retrieval: discovery often tags 'https' list proxies as 'http' for pragmatic connectivity.
        # We ensure these are included in the validation pool when 'https' type is requested.
        search_types = list(self.args.type)
        if "https" in search_types and "http" not in search_types:
            search_types.append("http")

        to_test = await self.db.get_candidates(search_types)
        if not to_test:
            logger.info("Database empty. Performing initial discovery...")
            to_test = await self.fetch_sources(sources, use_pivot=self.args.opsec)

        # Load proxies from JSON if requested
        json_path = self.args.update_json or self.args.validate_json
        if json_path:
            logger.info(f"Phase 1.5: Loading proxies from {json_path}...")
            try:
                p_path = Path(json_path)
                if p_path.exists():
                    data = json.loads(p_path.read_text())
                    proxies_data = data if isinstance(data, list) else data.get("proxies", [])
                    existing_ips = {p.ip for p in to_test}
                    added_count = 0
                    search_types = set(self.args.type)
                    if "https" in search_types:
                        search_types.add("http")
                        
                    for p_dict in proxies_data:
                        if all(k in p_dict for k in ("proto", "ip", "port")):
                            # Respect type filters even when loading from JSON
                            if p_dict['proto'] in search_types and p_dict['ip'] not in existing_ips:
                                p = Proxy(p_dict['proto'], p_dict['ip'], p_dict['port'], found_via=p_dict.get('found_via', 'JSON_LOAD'))
                                to_test.append(p)
                                existing_ips.add(p.ip)
                                added_count += 1
                    logger.info(f"Added {added_count} proxies from JSON matching types {self.args.type}.")
            except Exception as e:
                logger.error(f"Failed to load JSON file: {e}")

        logger.info(f" Validating {len(to_test)} proxies...")

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("[bold white]{task.completed}/{task.total}"),
            TextColumn("[bold green]✓ {task.fields[found]}[/]"),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
            disable=self.args.verbose
        )

        with progress:
            task = progress.add_task("Validating proxies...", total=len(to_test), found=0)

            async def worker(proxy: Proxy):
                if self.stop_event.is_set():
                    return
                    
                async with self.semaphore:
                    if self.stop_event.is_set():
                        return
                        
                    # Check for "fresh" verified status to skip redundant testing
                    if proxy.verified and proxy.checked_at:
                        try:
                            last_check = datetime.fromisoformat(proxy.checked_at)
                            if (datetime.now(timezone.utc) - last_check).total_seconds() < 86400:
                                if len(self.working) < self.args.limit:
                                    self.working.append(proxy)
                                    progress.update(task, found=len(self.working), advance=1)
                                    self.console.print(f"[bold cyan]fresh[/]  {proxy.proto.upper():7} {proxy.ip:15}:{proxy.port:<5} | (verified < 24h ago)")
                                    return
                        except Exception: pass

                    # If it is dead in the DB, skip validation if --skip-dead is set
                    if self.args.skip_dead and not proxy.working and proxy.checked_at:
                         progress.update(task, advance=1)
                         return

                    success = await self.check_proxy(proxy, use_pivot=self.args.opsec)
                    
                    if success and proxy.latency and proxy.latency <= self.args.max_latency:
                        country = proxy.country.upper()
                        if (not self.preferred or country in self.preferred) and country not in self.excluded:
                            if len(self.working) < self.args.limit:
                                self.working.append(proxy)
                                progress.update(task, found=len(self.working))
                                
                                self.console.print(
                                    f"[bold green]✓[/] {proxy.proto.upper():7} {proxy.ip:15}:{proxy.port:<5} "
                                    f"| {proxy.latency:5.2f}s | {proxy.anonymity:9} | {country:2} "
                                    f"| DNS: {'LEAK' if proxy.dns_leak else 'SAFE'}"
                                )
                                
                                if len(self.working) >= self.args.limit:
                                    self.stop_event.set()
                    else:
                        # Record failure to database
                        proxy.working = False
                        proxy.verified = False
                        proxy.checked_at = datetime.now(timezone.utc).isoformat()
                        await self.db.upsert(proxy)

                    progress.update(task, advance=1)

            # Use TaskGroup for better control (Python 3.11+)
            logger.debug(f"Scheduling {len(to_test)} validation workers via TaskGroup")
            try:
                async with asyncio.TaskGroup() as tg:
                    for p in to_test:
                        tg.create_task(worker(p))
            except* Exception as e:
                logger.error(f"TaskGroup error: {e}")
            finally:
                await self.db.close()

        self._save_results()

    def _save_results(self):
        """Sorts validated proxies and writes the proxychains config and JSON metadata files."""
        export_list = list(self.working)
        if self.args.chain_min_latency is not None:
            export_list = [p for p in export_list if p.latency is not None and p.latency <= self.args.chain_min_latency]

        if self.args.chain_shuffle:
            random.shuffle(export_list)
        else:
            export_list.sort(key=lambda p: (
                p.country.upper() not in self.preferred if self.preferred else False,
                p.anonymity != "Elite",
                p.latency or 9999
            ))

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        chain_map = {0: "dynamic_chain", 1: "random_chain", 2: "strict_chain"}
        chain = chain_map.get(self.args.chain_type, "dynamic_chain")
        chain_len = self.args.chain_length or self.args.limit

        config = f"""# proxychains.conf - NGF v{__version__}
# Generated: {timestamp} | Working Proxies: {len(self.working)}

{chain}
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
"""
        for p in export_list[:chain_len]:
            config += f"{p.proto} {p.ip} {p.port}\n"

        try:
            Path(self.args.output).write_text(config)
            logger.info(f"Saved {len(self.working)} working proxies to {self.args.output}")
        except PermissionError:
            logger.error(f"Permission denied: Could not write proxychains config to {self.args.output}")

        # JSON Export
        if self.args.json or self.args.update_json or self.args.validate_json:
            path = self.args.json or self.args.update_json or self.args.validate_json
            export = {
                "generated_at": timestamp,
                "version": __version__,
                "proxies": [p.to_dict() for p in export_list[:chain_len]]
            }
            try:
                Path(path).write_text(json.dumps(export, indent=2))
                logger.info(f"Metadata exported to {path}")
            except PermissionError:
                logger.error(f"Permission denied: Could not write JSON metadata to {path}")


async def main():
    parser = argparse.ArgumentParser(description="NGF v0.1.3 - Advanced Proxy Fetcher")
    # Operational Configurations
    parser.add_argument("--threads", type=int, default=DEFAULT_CONCURRENCY, help=f"Number of concurrent validation workers (default: {DEFAULT_CONCURRENCY})")
    parser.add_argument("--type", choices=["http", "https", "socks4", "socks5"], nargs="+", default=["socks5"], help="List of proxy protocols to harvest and validate (default: socks5)")
    parser.add_argument("--limit", type=int, default=MAX_PROXIES, help=f"Stop validation after finding this many working proxies (default: {MAX_PROXIES})")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    # JSON
    parser.add_argument("--json", help="Path to save the full proxy metadata as a JSON report")
    parser.add_argument("--update-json", help="Re-validate proxies from an existing JSON file and update their metadata")
    parser.add_argument("--validate-json", help="Validate proxies from a JSON file without performing new discovery")
    # Parsing
    parser.add_argument("--max-latency", type=float, default=DEFAULT_MAX_LATENCY, help=f"Maximum allowed latency in seconds for a proxy to be considered working (default: {DEFAULT_MAX_LATENCY})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"Request timeout in seconds for validation checks (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--country", help="Filter results to these country codes, comma-separated (e.g., US,GB,DE)")
    parser.add_argument("--exclude", help="Exclude these country codes from the final results, comma-separated (e.g., CN,RU)")
    # Proxychains
    parser.add_argument("-o", "--output", default="proxychains.conf", help="Path to save the generated proxychains configuration file (default: proxychains.conf)")
    parser.add_argument("--chain-type", type=int, choices=[0, 1, 2], default=0, help="Proxychains connection strategy: 0=dynamic_chain, 1=random_chain, 2=strict_chain (default: 0)")
    parser.add_argument("--chain-length", type=int, help="Number of proxies to include in the output configuration")
    parser.add_argument("--chain-shuffle", action="store_true", help="Randomize the order of proxies in the output")
    parser.add_argument("--chain-min-latency", type=float, help="Only include proxies in the chain with latency lower than this value")
    # Sources
    parser.add_argument("--source", help="Custom proxy source URLs (comma-separated)")
    parser.add_argument("--update-sources", action="store_true", help="Force refresh of candidates from external URLs")
    parser.add_argument("--skip-dead", action="store_true", help="Skip proxies marked as dead in the database")
    # Opsec
    parser.add_argument("--opsec", action="store_true", help="Enable stealth mode: route discovery and metadata audits through a pivot proxy")
    parser.add_argument("--proxy-only", action="store_true", help="Aggressive OpSec: force all traffic (including discovery) through a pivot, masking the host IP entirely")
    # Pivot
    parser.add_argument("--pivot", help="Specific proxy URL(s) to use as pivot (comma-separated, e.g. http://1.2.3.4:8080)")
    parser.add_argument("--pivot-http", action="store_true", help="Force the pivot search to prioritize HTTP/HTTPS proxies")
    parser.add_argument("--pivot-limit", type=int, help="Number of uses allowed per pivot proxy before rotating")
    # Database
    db_group = parser.add_argument_group("Database Management")
    db_group.add_argument("--db-dump", action="store_true", help="Dump proxy information from database")
    db_group.add_argument("--db-count", action="store_true", help="Show statistics about the database")
    db_group.add_argument("--db-ip", help="Filter DB dump by a specific IP address")
    db_group.add_argument("--db-country", help="Filter DB dump by country code (e.g., US)")
    db_group.add_argument("--db-proto", help="Filter DB dump by protocol (http, https, socks4, socks5)")
    db_group.add_argument("--db-anonymity", help="Filter DB dump by anonymity level (Elite, Anonymous, Transparent)")
    db_group.add_argument("--db-source", help="Filter DB dump by discovery source URL")
    db_group.add_argument("--db-max-latency", type=float, help="Filter DB dump by maximum latency")
    db_group.add_argument("--db-json", help="Export filtered database contents to a JSON file")
    db_group.add_argument("--db-import", help="Import proxy metadata from a JSON file into the database")
    db_group.add_argument("--db-clear", action="store_true", help="Wipe all data from the database")
    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    logger.warning("Using any form of free/unauthenticated proxies from public repo's are inheritly risky, use accordingly")

    fetcher = ProxyFetcher(args)

    if args.db_dump or args.db_count or args.db_json or args.db_import or args.db_clear:
        await fetcher.db.init()
        try:
            if args.db_clear:
                await fetcher.db.clear()
                CONSOLE.print("[bold green]✓[/] Database wiped successfully.")

            if args.db_count:
                stats = await fetcher.db.get_stats()
                CONSOLE.print(f"[bold blue]Database Statistics:[/]")
                CONSOLE.print(f"  Total Proxies:   [bold white]{stats['total']}[/]")
                CONSOLE.print(f"  Working Proxies: [bold green]{stats['working']}[/]")
                CONSOLE.print(f"  Dead Proxies:    [bold red]{stats['dead']}[/]")

                if stats.get('regions'):
                    CONSOLE.print(f"\n[bold blue]Proxies per Region:[/]")
                    for country, count in stats['regions']:
                        CONSOLE.print(f"  {country if country else '??':3}: [bold white]{count:>5}[/]")
            
            if args.db_dump:
                results = await fetcher.db.query_proxies(
                    ip=args.db_ip, 
                    country=args.db_country, 
                    max_latency=args.db_max_latency,
                    proto=args.db_proto,
                    anonymity=args.db_anonymity,
                    source=args.db_source
                )
                if not results:
                    CONSOLE.print("[yellow]No matching proxies found in database.[/]")
                else:
                    table = Table(title=f"NGF Database Export ({len(results)} entries)")
                    table.add_column("Proto", style="cyan")
                    table.add_column("Address", style="white")
                    table.add_column("Country", style="green")
                    table.add_column("Latency", style="magenta")
                    table.add_column("Anonymity", style="blue")
                    table.add_column("Source", style="dim")
                    table.add_column("Status", style="bold")
                    for p in results:
                        status = "[green]Working[/]" if p.working else "[red]Dead[/]"
                        src = (p.found_via[:30] + "..") if p.found_via and len(p.found_via) > 30 else (p.found_via or "Unknown")
                        table.add_row(
                            p.proto.upper(),
                            f"{p.ip}:{p.port}",
                            p.country,
                            f"{p.latency}s" if p.latency else "N/A",
                            p.anonymity,
                            src,
                            status
                        )
                    CONSOLE.print(table)

            if args.db_json:
                results = await fetcher.db.query_proxies(ip=args.db_ip, country=args.db_country, max_latency=args.db_max_latency)
                export = {
                    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "version": __version__,
                    "proxies": [p.to_dict() for p in results]
                }
                Path(args.db_json).write_text(json.dumps(export, indent=2))
                CONSOLE.print(f"[bold green]✓[/] Database exported to [bold white]{args.db_json}[/] ({len(results)} entries)")

            if args.db_import:
                import_path = Path(args.db_import)
                if not import_path.exists():
                    CONSOLE.print(f"[bold red]✗[/] Import file not found: [bold white]{args.db_import}[/]")
                else:
                    try:
                        data = json.loads(import_path.read_text())
                        proxies_data = data if isinstance(data, list) else data.get("proxies", [])
                        imported = 0
                        for p_dict in proxies_data:
                            if all(k in p_dict for k in ("proto", "ip", "port")):
                                p = Proxy(p_dict['proto'], p_dict['ip'], p_dict['port'], p_dict.get('found_via', 'IMPORT'))
                                p.working = p_dict.get('working', False)
                                p.latency = p_dict.get('latency')
                                p.anonymity = p_dict.get('anonymity', 'Unknown')
                                p.country = p_dict.get('country', '??')
                                p.city = p_dict.get('city', 'Unknown')
                                p.isp = p_dict.get('isp', 'Unknown')
                                p.org = p_dict.get('org', 'Unknown')
                                p.asn = p_dict.get('asn', 'Unknown')
                                p.dns_leak = p_dict.get('dns_leak')
                                p.verified = p_dict.get('verified', p.working)
                                p.checked_at = p_dict.get('checked_at')
                                await fetcher.db.upsert(p)
                                imported += 1
                        CONSOLE.print(f"[bold green]✓[/] Successfully imported [bold white]{imported}[/] proxies into the database.")
                    except Exception as e:
                        CONSOLE.print(f"[bold red]✗[/] Failed to import database: {e}")
        finally:
            await fetcher.db.close()
        return

    try:
        loop = asyncio.get_running_loop()
        # Wrap the runner in a task to allow cancellation on timeout
        fetcher_task = asyncio.create_task(fetcher.run())

        def shutdown_handler():
            if not fetcher.stop_event.is_set():
                logger.warning(f"Ctrl+C detected! Waiting up to {SHUTDOWN_TIMEOUT}s for threads to finish...")
                fetcher.stop_event.set()
                
                # Start a background task to enforce the grace period
                async def force_shutdown():
                    await asyncio.sleep(SHUTDOWN_TIMEOUT)
                    if not fetcher_task.done():
                        logger.error("Shutdown timed out. Forcing termination of remaining tasks.")
                        fetcher_task.cancel()
                
                loop.create_task(force_shutdown())
            else:
                logger.critical("Forced exit requested.")
                sys.exit(1)

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, shutdown_handler)
            except (NotImplementedError, ValueError):
                pass

        await fetcher_task
    except (KeyboardInterrupt, asyncio.CancelledError):
        # Ensure state is consistent and results are saved on exit
        fetcher.stop_event.set()
        fetcher._save_results()
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)


if __name__ == "__main__":
    asyncio.run(main())
