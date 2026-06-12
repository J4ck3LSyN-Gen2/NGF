#!/usr/bin/env python3
import asyncio, argparse, json, logging, os, random, re, sys, signal, time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Union
from urllib.parse import urlparse

import aiosqlite # type: ignore
from curl_cffi import requests # type: ignore
from rich.console import Console # type: ignore
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn, TimeElapsedColumn # type: ignore
from rich.logging import RichHandler # type: ignore
from rich.table import Table # type: ignore

__version__ = "0.1.5"
__author__ = "J4ck3LSyN"
__license__ = "MIT"

# ******************************** CONF ********************************
DEFAULT_TIMEOUT = 10
DEFAULT_MAX_LATENCY = 8.0
DEFAULT_CONCURRENCY = 40
DEFAULT_PIVOT_LIMIT = 100
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
        "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/socks5.txt", # Updated every 30 mins
        "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/main/MostStable/socks5.txt",
        "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/refs/heads/main/Stable/socks5.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
        "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt",
    ],
    "socks4": [
        "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/socks4.txt", # Updated every 30 mins
        "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/refs/heads/main/MostStable/socks4.txt",
        "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/refs/heads/main/Stable/socks4.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
        "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/SOCKS4_RAW.txt"
    ],
    "http": [
        "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/http.txt", # Updated every 30 mins
        "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/refs/heads/main/MostStable/http.txt",
        "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/refs/heads/main/Stable/http.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies.txt",
    ],
    "https": [
        "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/https.txt", # Updated every 30 mins
        "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/refs/heads/main/Stable/https.txt",
        "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/refs/heads/master/https.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt",
        "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/HTTPS_RAW.txt"
    ]
}

# ***************************** LOGGING ********************************
logger = logging.getLogger("NGF")
logger.setLevel(logging.INFO)

CONSOLE = Console()
rich_handler = RichHandler(console=CONSOLE, show_path=False, omit_repeated_times=False)
logger.addHandler(rich_handler)

# ******************************* PROXY ********************************
class proxy:
    def __init__(self,proto:str,ip:str,port:int,via:str="LOCAL"):
        # Essential information
        self.proto     = proto
        self.ip        = ip
        self.port      = port
        self.via       = via
        # Metadata
        self.city      = "Unknown"
        self.country   = "??"
        self.isp       = "Unknown"
        self.org       = "Unknown"
        self.asn       = "Unknown"
        self.anonymity = "Unknown"
        # Validation flags
        self.working   = False
        self.latency   = None
        self.verified  = False
        self.leakDNS  = False
        self.timeCheck = None
        self._extra     = {}  # Placeholder for any additional metadata

    def __repr__(self) -> str:
        status = "✓" if self.working else "✗"
        anon = self.anonymity[:3] if self.anonymity else "???"
        lat = f"{self.latency:.2f}s" if self.latency is not None else "??"
        return (f"<Proxy {status} {self.proto.upper()}://{self.ip}:{self.port} "
                f"| {self.country} | {anon} | {lat} | via:{self.via[:20]}...>")

    def __str__(self) -> str:
        return self.__repr__()

    def short(self) -> str:
        """Short representation for logs."""
        return f"{self.proto}://{self.ip}:{self.port}"

    def format_url(self)->str:
        prefix = "socks5h" if self.proto == "socks5" else self.proto
        return f"{prefix}://{self.ip}:{self.port}"
    
    def format_json(self)->Dict[str,Any]:
        return {k:v for k,v in self.__dict__.items() if not k.startswith("_")}


# ********************************  DB  ********************************
class PivotManager:
    """Thread-safe manager for pivot proxy state."""
    def __init__(self):
        self._lock = asyncio.Lock()
        self._pivot: Optional[proxy] = None
        self._usage = 0
        self._after_count = 0

    async def set_pivot(self, p: proxy):
        async with self._lock:
            self._pivot = p
            self._usage = 0
            logger.info(f"Pivot set to `{p.proto}://{p.ip}:{p.port}` (via: {p.via})")

    async def get_pivot(self) -> Optional[proxy]:
        async with self._lock:
            return self._pivot

    async def get_pivot_url(self) -> Optional[str]:
        async with self._lock:
            return self._pivot.format_url() if self._pivot else None

    async def clear_pivot(self):
        async with self._lock:
            self._pivot = None

    async def increment_usage(self, limit: Optional[int] = None) -> bool:
        """Increment usage and return True if rotation is needed."""
        async with self._lock:
            self._usage += 1
            if limit and self._usage >= limit:
                logger.info(f"Pivot reached usage limit ({limit}), scheduling rotation...")
                self._pivot = None
                return True
            return False

    async def increment_after_count(self, threshold: Optional[int] = None) -> bool:
        """Increment afterPivotCount and return True if pivot should be established."""
        async with self._lock:
            self._after_count += 1
            if threshold and self._after_count >= threshold:
                return True
            return False

    @property
    def after_count(self) -> int:
        return self._after_count  # Read-only for logging

class database:
    """SQLite backend for persistent proxy state and metadata."""
    # Initializers (__init__(on call: database()),init)
    # ---
    def __init__(self,path:str=DB_PATH,FALLBACK_TMP:Optional[bool]=False):
        self.path = path
        self.FALLBACK_TMP = FALLBACK_TMP
        self.db = None
        self._lock = asyncio.Lock()

    async def init(self):
        """Initialize database connection, tables, and performance optimizations."""
        dbp = Path(self.path).resolve()
        if not dbp.parent.exists():
            try:
                dbp.parent.mkdir(parents=True,exist_ok=True)
            except Exception as E:
                logger.critical(f"Failed to create database directory {dbp.parent}: {E}")
                sys.exit(1)

        if not os.access(dbp.parent,os.W_OK):
            logger.critical(f"Permission denied: Directory '{dbp.parent}' is not writable.")
            exit(1)

        try: self.db = await aiosqlite.connect(str(dbp))
        except Exception as E:
            logger.critical(f"Fatal error: Unable to open database file at {dbp}: {E}")
            sys.exit(1)

        try:
            await self.db.execute("PRAGMA busy_timeout = 5000")
            await self.db.execute("PRAGMA synchronous = NORMAL")
            await self.db.execute("PRAGMA temp_store = MEMORY")
            await self.db.execute("PRAGMA mmap_size = 2147483648") # 2GB
            await self.db.execute("PRAGMA locking_mode = EXCLUSIVE")
            await self.db.execute("PRAGMA cache_size = -128000")   # 128MB
        except Exception as e:
            logger.debug(f"Failed to set initial pragmas: {e}")

        table_sql = "CREATE TABLE IF NOT EXISTS idx (ip TEXT,proto TEXT,port INTEGER,working INTEGER,latency REAL,anonymity TEXT,country TEXT,city TEXT,isp TEXT,org TEXT,asn TEXT,leakDNS INTEGER,verified INTEGER,timeCheck TEXT,via TEXT, PRIMARY KEY(ip, port, proto))"
        try:
            await self.db.execute(table_sql)
        except Exception as e:
            if "disk I/O error" in str(e).lower():
                await self.db.execute("PRAGMA journal_mode = MEMORY")
                await self.db.execute(table_sql)
            else:
                raise

        try:
            await self.db.execute("PRAGMA journal_mode=WAL")
        except Exception as e:
            logger.debug(f"WAL mode not supported: {e}")

        for col in ["working", "country", "latency", "anonymity", "proto", "timeCheck"]:
            await self.db.execute(f"CREATE INDEX IF NOT EXISTS int_{col} ON idx({col})")
        await self.db.commit()

    # Index operations (get,query,...)
    # ---
    async def qIndex(self,ip:Optional[str]=None,country:Optional[str]=None,max_latency:Optional[float]=None,proto:Optional[str]=None,anonymity:Optional[str]=None,source:Optional[str]=None):
        """Queries(filters) the database for specific metadata."""
        async with self._lock:
            q = "SELECT proto,ip,port,working,latency,anonymity,country,city,isp,org,asn,leakDNS,verified,timeCheck,via FROM idx WHERE 1=1"
            params = []
            if ip:
                q += " AND ip = ?";params.append(ip)
            if country:
                q += " AND country = ?";params.append(country)
            if max_latency:
                q += " AND latency <= ?";params.append(max_latency)
            if proto:
                q += " AND proto = ?";params.append(proto)
            if anonymity:
                q += " AND anonymity = ?";params.append(anonymity)
            if source:
                q += " AND via = ?";params.append(source)
            async with self.db.execute(q,params) as cursor:
                rows = await cursor.fetchall()
                res  = []
                for r in rows:
                    p = proxy(r[0],r[1],r[2],r[14])
                    p.working,p.latency,p.anonymity,p.country,p.city,p.isp,p.org,p.asn = r[3:11]
                    p.working = bool(p.working)
                    p.leakDNS = bool(p.leakDNS) if r[11] is not None else False
                    p.verified = bool(p.verified)
                    p.timeCheck = r[13]
                    res.append(p)
                logger.debug(f"Pulled {str(len(res))} results, returning...")
                return res

    async def qWorking(self,ip:str)->bool:
        """Verify is an IP is existant and marked as working."""
        logger.debug(f"(qWorking) -> {ip}")
        async with self._lock:
            async with self.db.execute("SELECT 1 FROM idx WHERE ip = ? AND working = 1", (ip,)) as cursor:
                ret = await cursor.fetchone() is not None
                logger.debug(f"\t-> {ip}:{ret}")
                return ret

    async def aWorking(self,ips:List[str])->Set[str]:
        """Returns a set of IPs from the lsit that are marked as working."""
        logger.debug(f"(aWorking) -> {str(len(ips))} ips...")
        if not ips: return set()
        working = set()
        async with self._lock:
            for i in range(0,len(ips),900):
                chunk = ips[i:i+900]
                ph = ','.join(['?']*len(chunk))
                q = f"SELECT ip FROM idx WHERE ip IN ({ph}) AND working = 1"
                async with self.db.execute(q,chunk) as cursor:
                    rows = await cursor.fetchall()
                    for r in rows: working.add(r[0])
        logger.debug(f"(aWorking) Resolved {str(len(working))} working proxies...")
        return working

    async def qDead(self,ip:str)->bool:
        """Verify if an IP is existant and marked as dead."""
        logger.debug(f"(qDead) -> {ip}")
        async with self._lock:
            async with self.db.execute("SELECT 1 FROM idx WHERE ip = ? AND working = 0", (ip,)) as cursor:
                ret = await cursor.fetchone() is not None
                logger.debug(f"\t-> {ip}:{ret}")
                return ret

    async def aDead(self,ips:List[str])->Set[str]:
        """Returns a set of IPs from the list that are already marked as dead."""
        logger.debug(f"(aDead) -> {str(len(ips))} ips...")
        if not ips: return set()
        dead = set()
        async with self._lock:
            for i in range(0,len(ips),900):
                chunk = ips[i:i+900]
                ph = ','.join(['?']*len(chunk))
                q = f"SELECT ip FROM idx WHERE ip IN ({ph}) AND working = 0"
                async with self.db.execute(q,chunk) as cursor:
                    rows = await cursor.fetchall()
                    for r in rows: dead.add(r[0])
        logger.debug(f"(aDead) Resolved {str(len(dead))} dead proxies...")
        return dead

    async def gSeeds(self,types:List[str])->List[proxy]:
        """Fetches the most recent verified working procies to use as potential pivots."""
        logger.debug(f"(gSeeds) -> {str(len(types))} types...")
        async with self._lock:
            ph = ','.join(['?']*len(types))
            q = f"""
                SELECT proto,ip,port from idx
                WHERE working =1 AND proto in ({ph})
                ORDER BY timeCheck DESC LIMIT 150
            """
            async with self.db.execute(q,types) as cursor:
                rows = await cursor.fetchall()
                ret = [proxy(r[0],r[1],r[2]) for r in rows]
                logger.debug(f"(gSeeds) -> {str(len(ret))} proxies...")
                return ret

    async def gCandidates(self,types:List[str])->List[proxy]:
        """Fetches all candidates for re-validation."""
        logger.debug(f"(gCandidates) -> {str(len(types))} types...")
        async with self._lock:
            ph = ','.join(['?']*len(types))
            q = f"SELECT proto,ip,port,working,latency,anonymity,country,city,isp,org,asn,leakDNS,verified,timeCheck,via FROM idx WHERE proto IN ({ph})"
            async with self.db.execute(q,types) as cursor:
                rows = await cursor.fetchall()
                ret = []
                for r in rows:
                    p = proxy(r[0],r[1],r[2],r[14])
                    p.working = bool(r[3])
                    p.latency = r[4]
                    p.anonymity = r[5]
                    p.country = r[6]
                    p.city = r[7]
                    p.isp = r[8]
                    p.org = r[9]
                    p.asn = r[10]
                    p.leakDNS = bool(r[11]) if r[11] is not None else False
                    p.verified = bool(r[12])
                    p.timeCheck = r[13]
                    ret.append(p)
                logger.debug(f"(gCandidates) -> {str(len(ret))} proxies...")
                return ret

    # Internals (statistics,upsert,bUpsert,clear,close)
    async def statistics(self) -> Dict[str, Any]:
        """Return DB statistics."""
        logger.debug("(statistics) Initializing...")
        async with self._lock:
            stats = {
                "total": 0,
                "working": 0,
                "dead": 0,
                "verified": 0,
                "by_protocol": {},
                "by_country": {},
                "lowLatency": 0,
                "highLatency": 0,
                "elite": 0,
                "anonymous": 0,
                "transparent": 0
            }
            async with self.db.execute("SELECT COUNT(*) FROM idx") as cursor: stats["total"] = (await cursor.fetchone())[0]
            async with self.db.execute("SELECT COUNT(*) FROM idx WHERE working = 1") as cursor: stats["working"] = (await cursor.fetchone())[0]
            async with self.db.execute("SELECT COUNT(*) FROM idx WHERE verified = 1") as cursor: stats["verified"] = (await cursor.fetchone())[0]
            async with self.db.execute("SELECT COUNT(*) FROM idx WHERE working = 0 AND timeCheck IS NOT NULL") as cursor: stats["dead"] = (await cursor.fetchone())[0]
            
            async with self.db.execute("SELECT proto, COUNT(*) FROM idx GROUP BY proto") as cursor:
                stats["by_protocol"] = {r[0]: r[1] for r in await cursor.fetchall() if r[0]}
                
            async with self.db.execute("SELECT country, COUNT(*) FROM idx GROUP BY country ORDER BY COUNT(*) DESC") as cursor:
                rows = await cursor.fetchall()
                stats["by_country"] = {r[0] if r[0] else "Unknown": r[1] for r in rows}

            async with self.db.execute("SELECT COUNT(*) FROM idx WHERE latency <= 5.0") as cursor: stats["lowLatency"] = (await cursor.fetchone())[0]
            async with self.db.execute("SELECT COUNT(*) FROM idx WHERE latency > 5.0") as cursor: stats["highLatency"] = (await cursor.fetchone())[0]
            async with self.db.execute("SELECT COUNT(*) FROM idx WHERE anonymity = 'Elite'") as cursor: stats["elite"] = (await cursor.fetchone())[0]
            async with self.db.execute("SELECT COUNT(*) FROM idx WHERE anonymity = 'Anonymous'") as cursor: stats["anonymous"] = (await cursor.fetchone())[0]
            async with self.db.execute("SELECT COUNT(*) FROM idx WHERE anonymity = 'Transparent'") as cursor: stats["transparent"] = (await cursor.fetchone())[0]
            dstr = str(json.dumps(stats,indent=2)).replace("\n","\n\t-(stats)\t")
            logger.debug(f"Statistics: {dstr}")
            return stats

    async def upsert(self,p:proxy):
        """Inserts or updates proxy records."""
        logger.debug(f"(upsert) -> {p.ip} (Working: {p.working} | Latency: {p.latency})")
        async with self._lock:
            await self.db.execute("""
            INSERT OR REPLACE INTO idx (ip,proto,port,working,latency,anonymity,country,city,isp,org,asn,leakDNS,verified,timeCheck,via)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,(p.ip,p.proto,p.port,int(p.working),p.latency,p.anonymity,p.country,p.city,p.isp,p.org,p.asn,
                int(p.leakDNS) if p.leakDNS is not None else None,
                int(p.verified),p.timeCheck,p.via))
        await self.db.commit()

    async def bUpsert(self,proxies:List[proxy]):
        """Bulk insert/update for discovery phases."""
        logger.info(f"(bUpsert) Bulk inserting {len(proxies)} proxy candidates...")
        if not proxies: 
            logger.debug("No proxies to upsert!");return
        async with self._lock:
            try:
                # Ensure we are in a transaction for speed
                await self.db.execute("BEGIN")
                # Smaller chunk size to ensure we stay well under SQLITE_LIMIT_VARIABLE_NUMBER
                chunk_size = 500
                for i in range(0, len(proxies), chunk_size):
                    chunk = proxies[i:i+chunk_size]
                    data = [( p.ip,p.proto,p.port,int(p.working),p.latency, p.anonymity,p.country,p.city,p.isp,p.org,p.asn, int(p.leakDNS) if p.leakDNS is not None else None, int(p.verified),p.timeCheck,p.via) for p in chunk]
                    await self.db.executemany(
                        """
                        INSERT INTO idx (ip,proto,port,working,latency,anonymity,country,city,isp,org,asn,leakDNS,verified,timeCheck,via)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(ip, port, proto) DO UPDATE SET
                            working = CASE WHEN excluded.verified = 1 THEN excluded.working ELSE idx.working END,
                            verified = CASE WHEN excluded.verified = 1 THEN excluded.verified ELSE idx.verified END,
                            latency = CASE WHEN excluded.verified = 1 THEN excluded.latency ELSE idx.latency END,
                            anonymity = CASE WHEN excluded.verified = 1 THEN excluded.anonymity ELSE idx.anonymity END,
                            country = CASE WHEN excluded.verified = 1 OR (excluded.country IS NOT NULL AND excluded.country != '??') THEN excluded.country ELSE idx.country END,
                            city = CASE WHEN excluded.verified = 1 THEN excluded.city ELSE idx.city END,
                            isp = CASE WHEN excluded.verified = 1 THEN excluded.isp ELSE idx.isp END,
                            org = CASE WHEN excluded.verified = 1 THEN excluded.org ELSE idx.org END,
                            asn = CASE WHEN excluded.verified = 1 THEN excluded.asn ELSE idx.asn END,
                            leakDNS = CASE WHEN excluded.verified = 1 THEN excluded.leakDNS ELSE idx.leakDNS END,
                            timeCheck = CASE WHEN excluded.verified = 1 THEN excluded.timeCheck ELSE idx.timeCheck END,
                            via = excluded.via
                        """, data)
                await self.db.commit()
            except Exception as e:
                await self.db.rollback()
                logger.error(f"(bUpsert) Critical error during bulk database update: {e}")
                # We do not raise here to prevent stopping the entire fetcher, 
                # but the rollback ensures no partial/corrupt data is left.

    async def clear(self):
        """"""
        logger.debug(f"Clearing all entries from {self.path}")
        async with self._lock:
            await self.db.execute("DELETE FROM idx")
            await self.db.commit()
            await self.db.execute("VACUUM")

    async def close(self):
        """"""
        if self.db:
            await self.db.close()
            self.db = None

# ****************************** FETCHER *******************************
class NGFetcher:
    """
    """
    # Initialization
    def __init__(self,args:argparse.Namespace):
        logger.debug("Initializing fetcher...")
        self.args = args
        dbf = Path(args.db_path) / args.db_fname
        self.db = database(dbf)
        logger.debug("Database initialized... Initializing RICH...")
        self.console = CONSOLE
        self.hSession = requests.AsyncSession(impersonate="chrome110")
        self.vSession = requests.AsyncSession(impersonate="chrome110")
        logger.debug("...AsyncSessions initialized with `Chrome 110 TLS Impersonation...`")
        self.tSemaphore = asyncio.Semaphore(args.threads)
        self.aSemaphore = asyncio.Semaphore(8)
        logger.debug("...Semaphore's initialized... Establishing `lock` & `event`...")
        self.pEstLock = asyncio.Lock()
        self.termEvent = asyncio.Event()
        # Pivot manager testing...
        self._bg_tasks: Set[asyncio.Task] = set()
        self.pivot_mgr = PivotManager()
        logger.debug("...Pivot Locked & Stop Event Set..... Configuring internals...")
        self.working = []
        self.hAddr = None
        self.hCountry = None
        self.pref = {c.strip().upper() for c in (self.args.country or "").split(',') if c.strip()}
        self.excl = {c.strip().upper() for c in (self.args.exclude or "").split(',') if c.strip()}
        logger.debug(f"...Completed initialization...")

    async def _get_pivot_url(self, wait: bool = False) -> Optional[str]:
        """Retrieve the current pivot URL. Optionally wait/establish if missing."""
        purl = await self.pivot_mgr.get_pivot_url()
        if purl:
            return purl

        # If no pivot but we are in OpSec mode or told to wait
        if wait or self.args.opsec or self.args.proxy_only:
            if await self._estPivot():
                return await self.pivot_mgr.get_pivot_url()
        return None

    # Pivoting 
    async def _setPivot(self,p:proxy):
        """Updates the current pivot and resets usage count."""
        await self.pivot_mgr.set_pivot(p)

    async def _estPivot(self)->bool:
        """"""
        async with self.pEstLock:
            if await self.pivot_mgr.get_pivot(): return True
            logger.info("(_estPivot) Establishing...")
            if self.args.pivot:
                mUrls = [u.strip() for u in self.args.pivot.split(",") if u.strip()]
                logger.debug(f"(_estPivot) Testing candidates: `{str(mUrls)}`...")
                for u in mUrls:
                    try:
                        fu = u if "://" in u else f"http://{u}"
                        p = urlparse(fu)
                        proto = p.scheme or "http"
                        ip = p.hostname
                        port = p.port
                        if not ip or not port: raise ValueError(f"{u} is missing `hostname` or `port`!")
                        logger.debug(f"(_estPivot) Processing: `{str(fu)}`...")
                        pxy = proxy(proto.lower(),ip,port,via="MANUAL")
                        if await self.checkProxy(pxy):
                            await self._setPivot(pxy);return True
                    except Exception as E: logger.warning(f"(_estPivot) Failed to parse manual pivot `{u}` [{str(E.__class__.__name__)}]: `{str(E)}`")
            
            pTypes = ["http","https"] if self.args.pivot_http else self.args.type
            logger.debug(f"(_estPivot) ... Set pivot types to `{str(pTypes)}` ...")
            async def attempt(p:proxy)->bool:
                """Candidate validation helper."""
                if await self.checkProxy(p):
                    await self._setPivot(p);return True
                return False
            seeds = await self.db.gSeeds(pTypes)
            if seeds:
                logger.info(f"(_estPivot) Prioritizing {len(seeds)} seeds for rapid pivot recovery...")
                sTasks = [asyncio.create_task(attempt(s)) for s in seeds[:40]]
                for future in asyncio.as_completed(sTasks):
                    if await future:
                        for t in sTasks:
                            if not t.done(): t.cancel()
                        return True
            bsUrls = []
            sTypes = set(pTypes)
            if "https" in sTypes: sTypes.add("http")
            for t in sTypes: bsUrls.extend(PROXY_SOURCES.get(t,[])[:3])
            cans = await self.gSources(bsUrls)
            if cans:
                logger.debug(f"(_estPivot) Assessing {len(cans)} bootstrap candidates in parallel...")
                bTasks = [asyncio.create_task(attempt(p)) for p in cans[:20]]
                for future in asyncio.as_completed(bTasks):
                    if await future:
                        for t in bTasks:
                            if not t.done(): t.cancel()
                        return True
            logger.error("(_estPivot) Failed to establish pivot...")
            return False

    async def _hcPivot(self):
        """Periodically checks the health of the pivot proxy."""
        try:
            while not self.termEvent.is_set():
                await asyncio.sleep(60)
                if self.termEvent.is_set():
                    break

                pivot = await self.pivot_mgr.get_pivot()
                should_have_pivot = (self.args.proxy_only or self.args.opsec or 
                                    (self.args.pivot_after is not None and 
                                     self.pivot_mgr.after_count >= self.args.pivot_after))

                if not pivot and should_have_pivot:
                    await self._estPivot()
                elif pivot:
                    logger.debug(f"(_hcPivot) Assessing pivot `{pivot.ip}` health...")
                    if not await self.checkProxy(pivot):
                        logger.warning(f"(_hcPivot) Current pivot failed health check, rotating...")
                        await self.pivot_mgr.clear_pivot()
                        if should_have_pivot:
                            await self._estPivot()
        except asyncio.CancelledError:
            logger.debug("_hcPivot task cancelled.")
            raise
        except Exception as e:
            logger.error(f"_hcPivot encountered error: {e}")
        finally:
            logger.debug("_hcPivot shutting down.")

    # Proxies
    async def checkProxy(self,p:proxy,up:bool=False)->bool:
        """"""
        purl = p.format_url()
        target = random.choice(TEST_TARGETS)
        logger.debug(f"(checkProxy) Assessing `{p.proto}://{p.ip}:{p.port}` via `{target}`")
        if up:
            pivot_url = await self._get_pivot_url(wait=True)
            if pivot_url:
                current_pivot = await self.pivot_mgr.get_pivot()
                logger.debug(f"(checkProxy) [AUDIT] {current_pivot.ip if current_pivot else '??'} ↪ {p.ip} ↪ {target}")
                
                success = False
                for attempt in range(MAX_RETRIES + 1):
                    try:
                        async with self.aSemaphore:
                            aResp = await self.hSession.get(
                                f"http://ip-api.com/json/{p.ip}?fields=status,countryCode,city,isp,org,as",
                                proxy=pivot_url,
                                timeout=10)
                            
                            # Update usage through manager
                            limit = self.args.pivot_limit or DEFAULT_PIVOT_LIMIT if self.args.pivot_rotate else None
                            should_rotate = await self.pivot_mgr.increment_usage(
                                limit
                            )
                            if should_rotate:
                                asyncio.create_task(self._estPivot())
                            
                            if aResp.status_code == 200:
                                if not aResp.content:
                                    raise ValueError("(checkProxy) Empty reply from server!")
                                try:
                                    data = aResp.json()
                                    p.country = data.get("countryCode", p.country)
                                    p.city = data.get("city", p.city)
                                    p.isp = data.get("isp", p.isp)
                                    p.org = data.get("org", p.org)
                                    p.asn = data.get("as", p.asn)
                                    success = True
                                    break
                                except (json.JSONDecodeError, ValueError) as E:
                                    logger.warning(f"(checkProxy) Failed to parse JSON for `{p.ip}`: {E}")
                                    raise
                            elif aResp.status_code == 429:
                                logger.warning(f"(checkProxy) Rate limited on pivot. Retrying...")
                                await asyncio.sleep(5 * (attempt + 1))
                                continue
                    except Exception as E:
                        if self.args.proxy_only:
                            logger.error(f"(checkProxy) Metadata audit failed for `{p.ip}` via pivot and --proxy-only is enabled. Skipping.")
                            return False
                        eStr = str(E)
                        if attempt < MAX_RETRIES:
                            await asyncio.sleep(0.5 * (attempt + 1))
                            continue
                        logger.error(f"(checkProxy) Metadata audit failed for `{p.ip}` via pivot: {E}")
                if not success and not self.args.pivot:
                    return False

        if self.args.proxy_only:
            logger.debug(f"(checkProxy) Skipping direct validation for `{p.ip}` due to --proxy-only.")
            return False

        # Central validation logic (without pivot, if pivot failed, or awaiting pivots)
        for attempt in range(MAX_RETRIES+1):
            try:
                start = time.time()
                head  = {"User-Agent":random.choice(USER_AGENTS)}
                resp  = await self.vSession.get(target,proxy=purl,headers=head,timeout=self.args.timeout or DEFAULT_TIMEOUT)
                if resp.status_code == 200:
                    p.latency = round(time.time() - start,2)
                    logger.debug(f"(checkProxy) `{p.ip}` responded in {p.latency} seconds.")
                    data = resp.json() if resp.content else {}
                    oip = data.get("query") or data.get("ip") or data.get("origin") or ""
                    p.working = True
                    p.verified = True
                    p.timeCheck = datetime.now(timezone.utc).isoformat()
                    p.country = data.get("countryCode",p.country)
                    p.isp = data.get("isp",p.isp)
                    p.org = data.get("org",p.org)
                    p.asn = data.get("as",p.asn)
                    logger.info(f"(checkProxy) Proxy `{p.ip}` is working! Detected IP: `{oip}` | Country: `{p.country}` | ISP: `{p.isp}` | Org: `{p.org}` | ASN: `{p.asn}` | Latency: {p.latency}s")
                    # Anonymity assessment
                    if oip == p.ip: p.anonymity = "Elite"
                    elif self.hAddr and oip != self.hAddr: p.anonymity = "Anonymous"
                    else: p.anonymity = "Transparent"
                    # DNS Leak test (basic heuristic)
                    if not self.args.no_check_leak:
                        try:
                            dnsResp = await self.vSession.get("http://edns.ip-api.com/json",proxy=purl,timeout=8)
                            if dnsResp.status_code == 200:
                                dnsData = dnsResp.json() if dnsResp.content else {}
                                dnsGeo = dnsData.get("dns",{}).get("geo","")
                                if self.hCountry and p.country != "??":
                                    p.leakDNS = (self.hCountry in dnsGeo and p.country != self.hCountry)
                                    if p.leakDNS: logger.warning(f"(checkProxy) Potential DNS leak detected for `{p.ip}`! Host Country: `{self.hCountry}` | Proxy Country: `{p.country}` | DNS Geo: `{dnsGeo}`")
                                    else: logger.debug(f"(checkProxy) No DNS leak detected for `{p.ip}`. Host Country: `{self.hCountry}` | Proxy Country: `{p.country}` | DNS Geo: `{dnsGeo}`")
                        except: p.leakDNS = False
                    await self.db.upsert(p)
                    return True                        
                elif resp.status_code in (403,407):
                    logger.warning(f"(checkProxy) Proxy `{p.ip}` returned status code {resp.status_code} (Forbidden/Proxy Authentication Required). Attempt {attempt}/{MAX_RETRIES}. Retrying...")
                    await asyncio.sleep(2 * (attempt + 1))
                    continue
                elif resp.status_code == 401:
                    logger.warning(f"(checkProxy) Proxy `{p.ip}` returned status code 401 (Unauthorized). This may indicate an authentication requirement. Attempt {attempt}/{MAX_RETRIES}. Retrying...")
                    await asyncio.sleep(2 * (attempt + 1))
                    continue
            except Exception as E:
                eStr = f"(checkProxy) Caught exception for `{p.ip}` [{str(E.__class__.__name__)}]: `{str(E)}`"
                if "(28)" in str(E): eStr += " (Connection timed out)"
                elif "(52)" in str(E): eStr += " (Empty reply from server)"
                elif "(60)" in str(E): eStr += " (SSL certificate error)"
                elif "proxy error" in str(E).lower(): eStr += " (Proxy error)"
                elif "connection refused" in str(E).lower(): eStr += " (Connection refused by proxy)"
                logger.error(f"(checkProxy) [{eStr}]: Validation failed for `{p.ip}`...")
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
        # If we exhausted all attempts and haven't returned True, mark as False
        return False


    async def gSources(self, urls: List[str], up: bool = False) -> List[proxy]:
        """Fetch proxy lists from multiple sources."""
        # Tightened regex with word boundaries to avoid false positives and partial strings
        pat = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d):(\d{1,5})\b')
        
        async def single(u: str) -> List[proxy]:
            found = []
            try:
                fp = await self._get_pivot_url(wait=up) if up else None
                logger.debug(f"(gSources.single) Fetching `{u}` via {fp or 'DIRECT'}...")
                resp = await self.hSession.get(u, proxy=fp, timeout=25)
                
                if resp.status_code != 200:
                    logger.warning(f"(gSources.single) `{u}` returned {resp.status_code}")
                    return []
                
                # Update pivot usage if applicable through manager
                if up and fp:
                    limit = self.args.pivot_limit or DEFAULT_PIVOT_LIMIT if self.args.pivot_rotate else None
                    should_rotate = await self.pivot_mgr.increment_usage(
                        limit
                    )
                    if should_rotate:
                        asyncio.create_task(self._estPivot())
                
                dproto = "socks5" if "socks5" in u.lower() else "socks4" if "socks4" in u.lower() else "http"
                
                for match in pat.finditer(resp.text):
                    try:
                        ip_port = match.group(0)
                        ip, port = ip_port.split(":")
                        ip, port = ip.strip(), int(port)
                        if 1 <= port <= 65535:
                            found.append(proxy(dproto, ip, port, via=u))
                    except Exception:
                        continue

                if self.args.load_all:
                    # Clean up URL for display
                    display_url = u[:60] + "..." if len(u) > 63 else u
                    self.console.print(f"[bold blue][*][/] Source [cyan]{display_url:63}[/] -> [bold green]{len(found):>5}[/] proxies")

            except Exception as E:
                logger.error(f"(gSources.single) Failed on `{u}`: {E.__class__.__name__} - {E}")
            
            logger.debug(f"(gSources.single) Resolved {len(found)} proxies from `{u}`")
            return found
        
        # Run all source fetches concurrently
        res = await asyncio.gather(*(single(u) for u in urls), return_exceptions=True)
        
        unq: Dict[tuple, proxy] = {}
        for sublist in res:
            if isinstance(sublist, Exception):
                continue
            for p in sublist:
                key = (p.ip, p.port, p.proto)
                if key not in unq:
                    unq[key] = p
        
        logger.debug(f"(gSources) Identified {len(unq)} unique candidates from {len(urls)} sources")

        # Debugging: Log DB count before and after bUpsert
        initial_db_count = (await self.db.statistics()).get('total', 0)
        logger.debug(f"(gSources) DB total before bUpsert: {initial_db_count}")

        if not unq:
            logger.warning("(gSources) No valid candidates found")
            return []
        
        aCan = list(unq.values())
        await self.db.bUpsert(aCan)

        final_db_count = (await self.db.statistics()).get('total', 0)
        logger.debug(f"(gSources) DB total after bUpsert: {final_db_count}")
        logger.debug(f"(gSources) Net change in DB: {final_db_count - initial_db_count}")
        return aCan

    async def _load_json_raw(self, source: str) -> Any:
        """Load JSON either from a local path or a remote URL."""
        if source.startswith(("http://", "https://")):
            logger.info(f"(load_json) Fetching JSON from remote URL: {source}")
            try:
                async with self.aSemaphore:
                    resp = await self.hSession.get(source, timeout=25)
                if resp.status_code != 200:
                    raise ValueError(f"Remote JSON fetch failed with status {resp.status_code}")
                return json.loads(resp.text)
            except Exception as e:
                raise RuntimeError(f"Failed to load remote JSON from `{source}`: {e}")

        p_path = Path(source)
        if not p_path.exists():
            raise FileNotFoundError(f"JSON source not found: {source}")
        try:
            return json.loads(p_path.read_text())
        except Exception as e:
            raise RuntimeError(f"Failed to load JSON from `{source}`: {e}")

    def _normalize_json_proxy_data(self, data: Any) -> List[Dict[str, Any]]:
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("index") or data.get("proxies") or data.get("data") or []
        return []

    async def load_json_proxies(self, source: str) -> List[proxy]:
        raw = await self._load_json_raw(source)
        proxy_entries = self._normalize_json_proxy_data(raw)
        proxies: List[proxy] = []

        for item in proxy_entries:
            if not isinstance(item, dict):
                continue
            proto = str(item.get("proto", "")).lower()
            if not proto or "ip" not in item or "port" not in item:
                continue
            try:
                port = int(item["port"])
            except (ValueError, TypeError):
                continue
            proxies.append(proxy(proto, str(item["ip"]), port, via=f"JSON_LOAD({source})"))

        return proxies

    # Internals (save,run)
    async def gInfo(self):
        """Fetch host's public IP metadata"""
        logger.debug("(gInfo) Sourcing host's public metadata...")
        logger.info("... gInfo Uses `http://ip-api.com` for information gathering...")
        try:
            async with self.aSemaphore:
                resp = await self.hSession.get("http://ip-api.com/json/?fields=status,query,countryCode,city,isp,org,as",timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    self.hAddr = (data.get("query") or data.get("ip") or data.get("origin") or None)
                    self.hCountry = data.get("countryCode") or None
                    logger.info(
                        f"Host IP: `{self.hAddr}` | Country: `{self.hCountry}` | "
                        f"ISP: `{data.get('isp', 'Unknown')}` | Org: `{data.get('org', 'Unknown')}` | "
                        f"ASN: `{data.get('as', 'Unknown')}`")
                else:logger.warning(f"(gInfo) Failed to retrieve host information. Status code: {resp.status_code}")
        except Exception as E: logger.warning(f"(gInfo) Failed to retrieve host information: [{E.__class__.__name__}] {str(E)}")

    async def run(self):
        logger.info("Starting NGF Fetcher...")
        await self.db.init()

        # === Pivot / OpSec Setup ===
        if self.args.proxy_only or self.args.opsec:
            logger.debug("(run) Running in proxy-only or opsec mode, establishing pivot before harvesting...")
            if not await self._estPivot():
                logger.error("(run) Failed to establish initial pivot in proxy-only or opsec mode. Exiting...")
                return
            hc_task = asyncio.create_task(self._hcPivot())
            self._bg_tasks.add(hc_task)
            hc_task.add_done_callback(self._bg_tasks.discard)
        else:
            await self.gInfo()
            if self.args.pivot_after is not None:
                hc_task = asyncio.create_task(self._hcPivot())
                self._bg_tasks.add(hc_task)
                hc_task.add_done_callback(self._bg_tasks.discard)

        # === Source Collection ===
        sources = []
        for t in self.args.type:
            sources.extend(PROXY_SOURCES.get(t, []))
            if t == "https":
                sources.extend(PROXY_SOURCES.get("http", [])[:3])
            elif t == "http":
                sources.extend(PROXY_SOURCES.get("https", [])[:3])

        sources = list(dict.fromkeys(sources))
        logger.info(f"(run) Total unique sources to fetch from: {len(sources)}")

        if self.args.source:
            custom = [s.strip() for s in self.args.source.split(",") if s.strip()]
            sources.extend(custom)

        json_sources: List[str] = []
        if self.args.update_json:
            json_sources.append(self.args.update_json)
        if self.args.validate_json:
            json_sources.append(self.args.validate_json)
        if self.args.json_remote:
            json_sources.extend([u.strip() for u in self.args.json_remote.split(",") if u.strip()])

        # Load candidates
        sTypes = list(self.args.type)
        if "https" in sTypes and "http" not in sTypes:
            sTypes.append("http")

        test = await self.db.gCandidates(sTypes)
        logger.info(f"(run) Retrieved {len(test)} candidates from database...")

        # Update from web sources if requested or if DB is empty and no local JSON provided
        if self.args.load_all or self.args.update_sources or (not test and not json_sources):
            logger.info(f"(run) Fetching fresh sources from web (Mode: {'Load-All' if self.args.load_all else 'Update'})...")
            fresh = await self.gSources(sources, up=(self.args.opsec or self.args.proxy_only))

            if self.args.load_all:
                stats = await self.db.statistics()
                logger.info(f"(run) Load-all complete. Processed {len(fresh)} unique proxies from sources. Final total in database: {stats.get('total', 0)}")
                await self.db.close()
                return

            # Merge fresh candidates into test list
            existing_keys = {(p.ip, p.port, p.proto) for p in test}
            added = 0
            for p in fresh:
                if (p.ip, p.port, p.proto) not in existing_keys:
                    test.append(p)
                    existing_keys.add((p.ip, p.port, p.proto))
                    added += 1
            if added > 0:
                logger.info(f"(run) Added {added} fresh candidates from sources.")

        if not test and not json_sources:
            logger.error("(run) No candidates found in database or sources. Exiting...")
            return

        for json_source in json_sources:
            try:
                loaded_proxies = await self.load_json_proxies(json_source)
                existing_keys = {(p.ip, p.port, p.proto) for p in test}
                added_count = 0
                search_types = {t.lower() for t in self.args.type}
                if "https" in search_types:
                    search_types.add("http")

                for p in loaded_proxies:
                    if p.proto.lower() in search_types and (p.ip, p.port, p.proto) not in existing_keys:
                        test.append(p)
                        existing_keys.add((p.ip, p.port, p.proto))
                        added_count += 1

                logger.info(f"Added {added_count} proxies from JSON source `{json_source}` matching types {self.args.type}.")
            except Exception as e:
                logger.error(f"Failed to load JSON source `{json_source}`: {e}")


        # === Main Validation Loop ===
        logger.info(f"(run) Starting validation on {len(test)} candidates...")
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("[bold white]{task.completed}/{task.total}"),
            TextColumn("[bold green]✓ {task.fields[found]}[/]"),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
            disable=self.args.verbose)

        with progress:
            task = progress.add_task("Validating proxies...", total=len(test), found=0)

            async def worker(p: proxy):
                try:
                    async with self.tSemaphore:
                        if self.termEvent.is_set():
                            progress.update(task, advance=1)
                            return

                        # Pivot After Threshold
                        if self.args.pivot_after is not None:
                            should_establish = await self.pivot_mgr.increment_after_count(self.args.pivot_after)
                            if should_establish:
                                await self._estPivot()

                        # Skip recently verified
                        if p.working and p.verified and p.timeCheck:
                            try:
                                lastTime = datetime.fromisoformat(p.timeCheck)
                                if (datetime.now(timezone.utc) - lastTime).total_seconds() < 3600:
                                    if len(self.working) < self.args.limit:
                                        self.working.append(p)
                                        progress.update(task, advance=1, found=len(self.working))
                                        self.console.print(f"[bold cyan]✓[/] [white]\t[{p.proto.upper()}] {p.ip}:{p.port} | {p.country} | {p.isp} | Latency: {p.latency}s[/]")
                                        return
                            except Exception as E:
                                logger.error(f"(worker) Time parsing error for {p.ip}: {E}")

                        if self.args.skip_dead and not p.working and p.timeCheck:
                            progress.update(task, advance=1)
                            return

                        # Actual check
                        success = await self.checkProxy(
                            p, 
                            up=(self.args.opsec or bool(await self.pivot_mgr.get_pivot()))
                        )

                        if success and p.latency and p.latency <= self.args.max_latency:
                            country = p.country.upper() if p.country else "??"
                            if (not self.pref or country in self.pref) and country not in self.excl:
                                if len(self.working) < self.args.limit:
                                    self.working.append(p)
                                    progress.update(task, found=len(self.working))
                                    lat_str = f"{p.latency:5.2f}s" if p.latency is not None else "??.??s"
                                    self.console.print(
                                        f"[bold green]✓[/] {p.proto.upper():7} {p.ip:15}:{p.port:<5} "
                                        f"| {lat_str} | {p.anonymity:9} | {country:2} "
                                        f"| DNS: {'LEAK' if p.leakDNS else 'SAFE'} "
                                        f"| {p.isp} | {p.org}"
                                    )
                                    if len(self.working) >= self.args.limit:
                                        logger.info(f"Reached limit of {self.args.limit} working proxies. Stopping...")
                                        self.termEvent.set()
                        else:
                            p.working = False
                            p.verified = False
                            p.timeCheck = datetime.now(timezone.utc).isoformat()
                            await self.db.upsert(p)

                        progress.update(task, advance=1)

                except asyncio.CancelledError:
                    progress.update(task, advance=1)
                    raise
                except Exception as e:
                    logger.error(f"Worker error for {p.ip}: {e}")
                    progress.update(task, advance=1)

            logger.debug(f"(run) Scheduling {len(test)} validation tasks using worker pool...")
            try:
                # Initialize queue and populate it with candidates
                queue = asyncio.Queue()
                for p in test:
                    queue.put_nowait(p)

                async def worker_pool():
                    """Persistent worker that processes proxies from the queue."""
                    while not self.termEvent.is_set():
                        try:
                            p = queue.get_nowait()
                        except asyncio.QueueEmpty:
                            break
                        try:
                            await worker(p)
                        finally:
                            queue.task_done()

                async with asyncio.TaskGroup() as tg:
                    # Spawn exactly the number of configured threads as persistent workers
                    for _ in range(min(self.args.threads, len(test))):
                        tg.create_task(worker_pool())
            except* asyncio.CancelledError:
                logger.info("Validation tasks were cancelled.")
            except* Exception as exc:
                logger.error(f"(run) Caught exceptions during validation: {exc}")
            finally:
                logger.info(f"Validation complete. Found {len(self.working)} working proxies.")
                await self.db.close()

        logger.debug("(run) Saving results...")
        self.save()

    def save(self):
        """Save validated proxies to configuration and JSON files."""
        logger.debug("Saving results...")
        export_list = list(self.working)
        if self.args.chain_min_latency is not None:
            export_list = [p for p in export_list if p.latency is not None and p.latency >= self.args.chain_min_latency]
        
        if self.args.chain_shuffle:
            random.shuffle(export_list)
        else:
            export_list.sort(key=lambda p: (
            p.country.upper() not in self.pref if self.pref else False,
            p.anonymity != "Elite",
            p.latency or 9999))

        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H-%M-%S UTC")
        chain_modes = {0: "dynamic_chain", 1: "random_chain", 2: "strict_chain"}
        chain_type = chain_modes.get(self.args.chain_type, "dynamic_chain")
        cl = self.args.chain_length or len(export_list)
        config_lines = [
            f"# NGF 0.1.5 | {ts} | Working(?): {str(len(self.working))}",
            "",
            f"{chain_type}",
            "tcp_read_time_out 15000",
            "tcp_connect_time_out 8000",
            "",
            "[ProxyList]"]

        if self.args.append_tor:
            config_lines.append("socks5  127.0.0.1   9050")
        
        for p in export_list[:cl]:
            config_lines.append(f"{p.proto}  {p.ip}  {p.port}")

        output_name = self.args.output or f"ngf_{datetime.now().strftime('%H-%M')}.config"
        opath = Path(self.args.output_path) / output_name if self.args.output_path else Path(output_name)
        
        try:
            if opath.parent: opath.parent.mkdir(parents=True, exist_ok=True)
            opath.write_text("\n".join(config_lines))
            logger.info(f"Saved proxychains config: `{opath}`")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")

        json_path_str = self.args.json or self.args.update_json or self.args.validate_json
        if json_path_str:
            jpath = Path(self.args.output_path) / json_path_str if self.args.output_path else Path(json_path_str)
            try:
                if jpath.parent: jpath.parent.mkdir(parents=True, exist_ok=True)
                idx = [p.format_json() for p in export_list[:cl]]
                export_data = {
                    "timestamp": ts,
                    "version": __version__,
                    "author": __author__,
                    "index": idx,
                    "count": len(idx)
                }
                jpath.write_text(json.dumps(export_data, indent=self.args.indent_json))
                logger.info(f"Exported JSON metadata: `{jpath}`")
            except Exception as e:
                logger.error(f"Failed to export JSON: {e}")
            

# ******************************** INIT ********************************
async def _cleanup_background_tasks(tasks: Set[asyncio.Task], fetcher: NGFetcher):
    """Helper to cleanly cancel and await background tasks."""
    all_tasks = tasks.union(getattr(fetcher, '_bg_tasks', set()))
    if not all_tasks:
        return
    logger.debug(f"Cleaning up {len(all_tasks)} background tasks...")
    for task in all_tasks:
        if not task.done():
            task.cancel()
    if all_tasks:
        await asyncio.gather(*all_tasks, return_exceptions=True)
    # Close DB if still open
    if hasattr(fetcher, 'db') and fetcher.db and fetcher.db.db:
        try:
            await fetcher.db.close()
        except:
            pass

async def main():
    parser = argparse.ArgumentParser(description="NGF v0.1.5 - Advanced Proxy Fetcher")
    # Operational Configurations
    parser.add_argument("--threads", type=int, default=DEFAULT_CONCURRENCY, help=f"Number of concurrent validation workers (default: {DEFAULT_CONCURRENCY})")
    parser.add_argument("--type", choices=["http", "https", "socks4", "socks5"], nargs="+", default=["socks5"], help="List of proxy protocols to harvest and validate (default: socks5)")
    parser.add_argument("--limit", type=int, default=MAX_PROXIES, help=f"Stop validation after finding this many working proxies (default: {MAX_PROXIES})")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--show-config", action="store_true", help="Display the effective configuration")
    # JSON
    parser.add_argument("--json", help="Path to save the full proxy metadata as a JSON report")
    parser.add_argument("--update-json", help="Re-validate proxies from an existing JSON file and update their metadata")
    parser.add_argument("--validate-json", help="Validate proxies from a JSON file without performing new discovery")
    parser.add_argument("--json-remote", help="Load proxy metadata from a remote JSON URL (comma-separated for multiple URLs)")
    parser.add_argument("--indent-json", type=int, default=2, help="Indentation for `json` output.")
    # Parsing
    parser.add_argument("--max-latency", type=float, default=DEFAULT_MAX_LATENCY, help=f"Maximum allowed latency in seconds for a proxy to be considered working (default: {DEFAULT_MAX_LATENCY})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"Request timeout in seconds for validation checks (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--country", help="Filter results to these country codes, comma-separated (e.g., US,GB,DE)")
    parser.add_argument("--exclude", help="Exclude these country codes from the final results, comma-separated (e.g., CN,RU)")
    # Proxychains
    parser.add_argument("-o", "--output", help="Path to save the generated proxychains configuration file (default: ngf_HH-MM.config)")
    parser.add_argument("--output-path", type=str, default="ngfdata", help="Path to save output files (default: ngfdata)")
    parser.add_argument("--chain-type", type=int, choices=[0, 1, 2], default=0, help="Proxychains connection strategy: 0=dynamic_chain, 1=random_chain, 2=strict_chain (default: 0)")
    parser.add_argument("--chain-length", type=int, help="Number of proxies to include in the output configuration")
    parser.add_argument("--chain-shuffle", action="store_true", help="Randomize the order of proxies in the output")
    parser.add_argument("--chain-min-latency", type=float, help="Only include proxies in the chain with latency lower than this value")
    parser.add_argument("--append-tor", action="store_true", help="Appends `tor` to the head of the proxychains.conf file.")
    # Sources
    parser.add_argument("--source", help="Custom proxy source URLs (comma-separated)")
    parser.add_argument("--update-sources", action="store_true", help="Force refresh of candidates from external URLs")
    parser.add_argument("--load-all", action="store_true", help="Fetch and load all proxies from all sources into the database, display source statistics, and exit.")
    parser.add_argument("--skip-dead", action="store_true", help="Skip proxies marked as dead in the database")
    # Opsec
    parser.add_argument("--opsec", action="store_true", help="Enable stealth mode: route discovery and metadata audits through a pivot proxy")
    parser.add_argument("--proxy-only", action="store_true", help="Aggressive OpSec: force all traffic (including discovery) through a pivot, masking the host IP entirely")
    # Pivot
    parser.add_argument("--pivot", help="Specific proxy URL(s) to use as pivot (comma-separated, e.g. http://1.2.3.4:8080)")
    parser.add_argument("--pivot-http", action="store_true", help="Force the pivot search to prioritize HTTP/HTTPS proxies")
    parser.add_argument("--pivot-rotate", action="store_true", help="Enable automatic pivot rotation based on usage limits")
    parser.add_argument("--pivot-after", type=int, help="Initialize pivot after validating this many candidates without a pivot")
    parser.add_argument("--pivot-limit", type=int, help="Number of uses allowed per pivot proxy before rotating")
    parser.add_argument("--no-check-leak", action="store_true", help="Skip the DNS leak test during proxy validation (may reduce accuracy of anonymity assessment)")
    # Database
    db_group = parser.add_argument_group("Database Management")
    db_group.add_argument("--db-fname", help="Name of the SQLite database file. Default: ngf_state.db", default="ngf_state.db")
    db_group.add_argument("--db-path", help="Path to the SQLite database file (Will be created if non-existant)", default="ngfdata")
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
    if args.verbose: logger.setLevel(logging.DEBUG)
    logger.warning("Using any form of free/unauthenticated proxies from public repo's are inheritly risky, use accordingly")
    if args.show_config:
        border = "+" + "-" * 67 + "+"
        header = f"|{'NGF v' + __version__ + ' CONFIGURATION':^67}|"
        CONSOLE.print(f"[bold cyan]{border}[/]")
        CONSOLE.print(f"[bold cyan]{header}[/]")
        CONSOLE.print(f"[bold cyan]{border}[/]")
        CONSOLE.print(f"[bold cyan]| Threads       : {str(args.threads):<14} | Protocols     : {', '.join(args.type):<14} |[/]")
        CONSOLE.print(f"[bold cyan]| Limit         : {str(args.limit):<14} | Max Latency   : {str(args.max_latency):<14} |[/]")
        output_disp = args.output if args.output else "TIMED-AUTO"
        CONSOLE.print(f"[bold cyan]| Timeout       : {str(args.timeout):<14} | Output        : {output_disp:<14} |[/]")
        CONSOLE.print(f"[bold cyan]| OpSec         : {str(args.opsec):<14} | Proxy Only    : {str(args.proxy_only):<14} |[/]")
        CONSOLE.print(f"[bold cyan]| Skip Dead     : {str(args.skip_dead):<14} | Append Tor    : {str(args.append_tor):<14} |[/]")
        CONSOLE.print(f"[bold cyan]| Pivot         : {str(args.pivot):<14} | Chain Type    : {str(args.chain_type):<14} |[/]")
        CONSOLE.print(f"[bold cyan]| Chain Length  : {str(args.chain_length):<14} | Chain Min     : {str(args.chain_min_latency):<14} |[/]")
        CONSOLE.print(f"[bold cyan]| Chain Shuffle : {str(args.chain_shuffle):<14} | DB Name       : {str(args.db_fname):<14} |[/]")
        CONSOLE.print(f"[bold cyan]| Pivot Rotate  : {str(args.pivot_rotate):<14} | Pivot After   : {str(args.pivot_after):<14} |[/]")
        CONSOLE.print(f"[bold cyan]| DB Path       : {str(args.db_path):<47} |[/]")
        CONSOLE.print(f"[bold cyan]{border}[/]\n")

    fetcher = NGFetcher(args)
    # Database management mode
    if args.db_dump or args.db_count or args.db_json or args.db_import or args.db_clear:
        logger.debug("Database management mode detected. Initializing database operations...")
        await fetcher.db.init()
        try:
            if args.db_clear:
                confirm = input("[bold red]![/]Are you sure you want to clear all data from the database? This action cannot be undone! (yes/no): ")
                if confirm.lower() == "yes":
                    await fetcher.db.clear()
                    CONSOLE.print(f"[bold green]✓[/] Database wiped successfully.")
                else: CONSOLE.print(f"[bold yellow]⚠[/] Database clear operation cancelled.")
            if args.db_count:
                stats = await fetcher.db.statistics()
                CONSOLE.print(f"[bold cyan]Database Statistics:[/]")
                CONSOLE.print(f"  - Total Proxies: {stats.get('total',0)}")
                CONSOLE.print(f"  - Verified: {stats.get('verified',0)}")
                CONSOLE.print(f"  - Working: {stats.get('working',0)}")
                CONSOLE.print(f"  - By Protocol: {json.dumps(stats.get('by_protocol',{}),indent=2)}")
                CONSOLE.print(f"  - By Country: {json.dumps(stats.get('by_country',{}),indent=2)}")
            if args.db_dump:
                res = await fetcher.db.qIndex(
                    ip=args.db_ip,
                    country=args.db_country,
                    proto=args.db_proto,
                    anonymity=args.db_anonymity,
                    source=args.db_source,
                    max_latency=args.db_max_latency)
                if not res: CONSOLE.print(f"[bold yellow]⚠[/] No entries found matching the specified filters.")
                else:
                    table = Table(title=f"NGF015 DB Export ({len(res)} entries)", show_header=True, header_style="bold magenta")
                    table.add_column("IP:Port", style="cyan")
                    table.add_column("Proto", style="green")
                    table.add_column("Country", style="yellow")
                    table.add_column("Anonymity", style="blue")
                    table.add_column("Latency", style="red")
                    table.add_column("Source", style="white")
                    for p in res:
                        status = "[bold green]Working[/]" if p.working else "[bold red]Dead[/]"
                        src = (p.via[:30] + "...") if p.via and len(p.via) > 33 else (p.via or "Unknown")
                        table.add_row(
                            f"{p.ip}:{p.port}",
                            p.proto.upper(),
                            p.country or "??",
                            p.anonymity or "Unknown",
                            f"{p.latency:.2f}s" if p.latency else "N/A",
                            src)
                    CONSOLE.print(table)
            if args.db_json:
                path = Path(args.db_json)
                try:
                    res = await fetcher.db.qIndex(
                        ip=args.db_ip,
                        country=args.db_country,
                        proto=args.db_proto,
                        anonymity=args.db_anonymity,
                        source=args.db_source,
                        max_latency=args.db_max_latency)
                    pdata = [p.format_json() for p in res]
                    export = {
                        "timestamp":datetime.now(timezone.utc).isoformat(),
                        "version":__version__,
                        "author":__author__,
                        "count":len(pdata),
                        "index":pdata}
                    path.write_text(json.dumps(export,indent=fetcher.args.indent_json))
                    CONSOLE.print(f"[bold green]✓[/] Successfully exported database entries to `{str(path)}` ({len(pdata)} entries)...")
                except PermissionError:
                    logger.error(f"PermissionError: Failed to write to `{str(path)}`!")
                except Exception as E:
                    logger.error(f"Caught Exception: Un-expected exception during operation: `{str(E)}`!")
            if args.db_import:
                try:
                    jdata = await fetcher._load_json_raw(args.db_import)
                    pdata = jdata if isinstance(jdata, list) else jdata.get("index") or jdata.get("proxies") or jdata.get("data") or []
                    imported_proxies = []
                    for pD in pdata:
                        if not isinstance(pD, dict):
                            continue
                        if all(k in pD for k in ("ip","port","proto")):
                            try:
                                p = proxy(pD["proto"], pD["ip"], pD["port"], via=f"DB_IMPORT({args.db_import})")
                                p.country = pD.get("country")
                                p.city = pD.get("city")
                                p.isp = pD.get("isp")
                                p.org = pD.get("org")
                                p.asn = pD.get("asn")
                                p.verified = bool(pD.get("verified", False))
                                p.working = bool(pD.get("working", False))
                                p.latency = pD.get("latency")
                                p.timeCheck = pD.get("timeCheck")
                                imported_proxies.append(p)
                            except Exception as E:
                                logger.warning(f"(db_import) Failed to parse proxy entry from JSON `{args.db_import}`: [{str(E.__class__.__name__)}] `{str(E)}`")
                    if imported_proxies:
                        await fetcher.db.bUpsert(imported_proxies)
                    CONSOLE.print(f"[bold green]✓[/] Successfully imported {len(imported_proxies)} entries from `{args.db_import}` into the database.")
                except Exception as E:
                    logger.error(f"(db_import) Failed to import from JSON `{args.db_import}`: [{str(E.__class__.__name__)}] `{str(E)}`")
        finally:
            logger.debug("Closing database connection...")
            try: await fetcher.db.close()
            except Exception as E: logger.warning(f"(main) Failed to close database [{str(E.__class__.__name__)}]: `{str(E)}`")
        return
    # Normal operation mode
    background_tasks: Set[asyncio.Task] = set()
    fTask = None
    try:
        fTask = asyncio.create_task(fetcher.run())
        def termHandle():
            if fetcher.termEvent.is_set():
                logger.critical("Second termination signal received. Forcing immediate shutdown...")
                sys.exit(1)
                return
            logger.warning("Termination signal (Ctrl+C) received. Shutting down gracefully...")
            fetcher.termEvent.set()
            if fTask and not fTask.done(): fTask.cancel()
            # Force cleanup after timeout
            async def force_cleanup():
                await asyncio.sleep(SHUTDOWN_TIMEOUT)
                if fTask and not fTask.done():
                    logger.warning(f"Forcing shutdown after {SHUTDOWN_TIMEOUT}s timeout...")
                    fTask.cancel()
            force_task = asyncio.create_task(force_cleanup())
            background_tasks.add(force_task)
            force_task.add_done_callback(lambda t: background_tasks.discard(t))
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try: loop.add_signal_handler(sig, termHandle)
            except (NotImplementedError, ValueError): pass
        await fTask
    except asyncio.CancelledError: logger.warning("Main task was cancelled.")
    except (KeyboardInterrupt, Exception) as e:
        if isinstance(e, KeyboardInterrupt): logger.warning("KeyboardInterrupt received.")
        else: logger.error(f"Unexpected error: {e}")
        fetcher.termEvent.set()
        fetcher.save()
    finally: 
        await _cleanup_background_tasks(background_tasks, fetcher)
        # Close HTTP sessions
        for session_attr in ('hSession', 'vSession'):
            session = getattr(fetcher, session_attr, None)
            if session:
                try: await session.close()
                except: pass
        logger.info("NGF shutdown complete.")

if __name__ == "__main__": asyncio.run(main())
