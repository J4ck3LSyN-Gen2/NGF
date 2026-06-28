#!/usr/bin/env python3
import asyncio, argparse, json, logging, os, random, re, sys, signal, time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Union, Tuple
from urllib.parse import urlparse
from dataclasses import dataclass, field

import aiosqlite
from curl_cffi import requests 
from rich.console import Console 
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn, TimeElapsedColumn 
from rich.logging import RichHandler 
from rich.table import Table
import yaml # For loading configs

__version__ = "0.1.6"
__author__ = "J4ck3LSyN"
__license__ = "MIT"

#> Regex for IP:PORT extraction (without word boundaries)
IP_PORT_REGEX_PATTERN = r"(?<!\d)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):(?:[0-9]{1,5})(?!\d)"
#> Configuration
DEFAULT_CONFIG_PATH = "./ngf_config.json"
DEFAULT_CONFIG = {
    "CONN":{
        "TIMEOUT": 10,
        "MAX_LATENCY": 8.0,
        "CONCURRENCY_LIMIT": 16,
        "NETWORK_CONCURRENCY_LIMIT": 100,
        "PIVOT_USAGE_LIMIT": 32,
        "MAX_PROXY_LIMIT": 1000,
        "MAX_RETRIES": 2,
        "SHUTDOWN_TIMEOUT": 15,
        "DBROOT":".", # Directory 
        "DBPATH": "ngf_state.db" # Fname
    },
    "USER_AGENTS": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
    ],
    "VALIDATION_TARGETS": [
        "http://ip-api.com/json?fields=status,message,countryCode,city,isp,org,as,query",
        "https://api.ipify.org?format=json",
        "https://ifconfig.co/json",
        "https://ipinfo.io/json",
    ],
    "SOURCE_URLS": {
        "socks5": [
            "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/socks5.txt",
            "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/main/MostStable/socks5.txt",
            "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/refs/heads/main/Stable/socks5.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
            "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt",
        ],
        "socks4": [
            "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/socks4.txt",
            "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/main/MostStable/socks4.txt",
            "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/refs/heads/main/Stable/socks4.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt"
        ],
        "http": [
            "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/http.txt",
            "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/main/MostStable/http.txt",
            "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/refs/heads/main/Stable/http.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
            "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
            "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies.txt",
        ],
        "https": [
            "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/https.txt",
            "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/refs/heads/main/Stable/https.txt",
            "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/refs/heads/master/https.txt",
            "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt",
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/HTTPS_RAW.txt"
        ]
    }
}

def load_config_file(fp: str) -> Dict[str, Any]:
    path = Path(fp)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file @ `{fp}` was not found!")
    with open(fp, 'r', encoding='utf-8') as f:  # Use fp, not file_path
        if fp.lower().endswith(('.yaml', '.yml')):
            config = yaml.safe_load(f)
        else:
            config = json.load(f)
    if not isinstance(config, dict):
        raise ValueError("Configuration file must contain a top-level object/dictionary.")
    
    final_conf = DEFAULT_CONFIG.copy()
    final_conf.update(config)
    for key in ['CONN', 'USER_AGENTS', 'VALIDATION_TARGETS', 'SOURCE_URLS']:
        if key in config and isinstance(config[key], dict) and isinstance(final_conf[key], dict):
            final_conf[key].update(config[key])
    return final_conf

def apply_config(config:Dict[str,Any], args:argparse.Namespace):
    if args.timeout is not None: config['CONN']['TIMEOUT'] = args.timeout
    if args.max_latency is not None and args.max_latency != DEFAULT_CONFIG['CONN']['MAX_LATENCY']: config['CONN']['MAX_LATENCY'] = args.max_latency
    if args.threads != DEFAULT_CONFIG['CONN']['CONCURRENCY_LIMIT']: config['CONN']['CONCURRENCY_LIMIT'] = args.threads
    if args.network_concurrency != DEFAULT_CONFIG['CONN']['NETWORK_CONCURRENCY_LIMIT']: config['CONN']['NETWORK_CONCURRENCY_LIMIT'] = args.network_concurrency
    if args.limit != DEFAULT_CONFIG['CONN']['MAX_PROXY_LIMIT']: config['CONN']['MAX_PROXY_LIMIT'] = args.limit
    if args.pivot_limit_if_set != DEFAULT_CONFIG['CONN']['PIVOT_USAGE_LIMIT']: config['CONN']['PIVOT_USAGE_LIMIT'] = args.pivot_limit_if_set
    if hasattr(args, 'db_filepath') and args.db_filepath != DEFAULT_CONFIG['CONN']['DBPATH']: config['CONN']['DBPATH'] = args.db_filepath
    if hasattr(args, 'db_json_export') and args.db_json_export:
        config.setdefault('DB', {})['JSON_EXPORT'] = args.db_json_export
    return config
    if args.type:
         if "SOURCE_URLS" not in config: config["SOURCE_URLS"] = DEFAULT_CONFIG["SOURCE_URLS"].copy()
         selected_sources = {"http": [], "https": [], "socks4": [], "socks5": []}
         for t in args.type:
            if t in config["SOURCE_URLS"]:
                selected_sources[t] = list(config["SOURCE_URLS"][t])
         config["SOURCE_URLS"] = selected_sources
    return config
#>Logging
logger = logging.getLogger("NGF")
logger.setLevel(logging.INFO)

CONSOLE = Console()
rich_handler = RichHandler(console=CONSOLE, show_path=False, omit_repeated_times=False)
logger.addHandler(rich_handler)
#>proxy dataclass
@dataclass
class proxy:
    # Main data
    proto:str
    ip:str
    port:int
    via:str ="LOCAL"
    # Information
    city: str = "Unknown"
    country: str = "??"
    isp: str = "Unknown"
    org: str = "Unknown"
    asn: str = "Unknown"
    anonymity: str = "Unknown"
    # Metadata verifiers
    working: bool = False
    latency: Optional[float] = None
    verified: bool = False
    leak_dns: bool = False
    time_check: Optional[str] = None
    dns_leak_test_latency: Optional[float] = None
    # Extra appended data
    _extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not re.match(IP_PORT_REGEX_PATTERN.replace(r"(?<!\d)", "").replace(r"(?!\d)", ""), f"{self.ip}:{self.port}"): raise ValueError(f"Invalid IP:Port combination: {self.ip}:{self.port}")
        if self.port < 1 or self.port > 65535: raise ValueError(f"Port out of range: {self.port}")
        if self.proto.lower() not in ["socks4", "socks5", "http", "https"]: raise ValueError(f"Invalid protocol: {self.proto}")

    def __repr__(self) -> str:
        status = "✓" if self.working else "✗"
        anon = self.anonymity[:3] if self.anonymity else "???"
        lat = f"{self.latency:.2f}s" if self.latency is not None else "??"
        return (f"<Proxy {status} {self.proto.upper()}://{self.ip}:{self.port} "
                f"| {self.country} | {anon} | {lat} | via:{self.via[:20]}...>")

    def short(self) -> str:
        return f"{self.proto}://{self.ip}:{self.port}"

    def format_url(self) -> str:
        """Return properly formatted proxy URL for curl_cffi / requests."""
        if self.proto == "socks5": return f"socks5h://{self.ip}:{self.port}"
        elif self.proto in ("http", "https"): return f"http://{self.ip}:{self.port}"
        else: return f"{self.proto}://{self.ip}:{self.port}"
    
    def format_json(self)->Dict[str,Any]:
        data = {}
        for attr_name in ['proto', 'ip', 'port', 'via', 'city', 'country', 'isp', 'org', 'asn', 'anonymity',
                           'working', 'latency', 'verified', 'leak_dns', 'time_check', 'dns_leak_test_latency', '_extra']:
            if attr_name != '__dataclass_fields__':
                attr_value = getattr(self, attr_name)
                data[attr_name] = attr_value
        return data
#>Pivot Manager
class PivotManager:
    def __init__(self):
        self._lock = asyncio.Lock()
        self._pivot: Optional[proxy] = None
        self._usage = 0
        self._validation_count = 0
        self._blacklist: Dict[str, float] = {}

    async def blacklist_ip(self, ip: str, duration: int = 300):
        async with self._lock:
            self._blacklist[ip] = time.time() + duration
            logger.debug(f"Pivot IP {ip} blacklisted for {duration}s")

    async def is_blacklisted(self, ip: str) -> bool:
        async with self._lock:
            expiry = self._blacklist.get(ip)
            if expiry:
                if time.time() < expiry: return True
                else: del self._blacklist[ip]
            return False

    async def set_pivot(self, p: proxy):
        async with self._lock:
            old_ip = self._pivot.ip if self._pivot else "None"
            self._pivot = p
            self._usage = 0
            logger.info(f"Pivot changed from '{old_ip}' to '{p.format_url()}' (via: {p.via})")

    async def get_pivot(self) -> Optional[proxy]:
        async with self._lock:
            return self._pivot

    async def get_pivot_url(self) -> Optional[str]:
        async with self._lock:
            return self._pivot.format_url() if self._pivot else None

    async def clear_pivot(self):
        async with self._lock:
            self._pivot = None

    async def increment_usage(self, limit: Optional[int]) -> bool:
        async with self._lock:
            self._usage += 1
            if limit is not None and self._usage >= limit:
                logger.info(f"Pivot ({self._pivot.ip if self._pivot else '??'}) reached usage limit ({limit}), will rotate...")
                return True 
            return False

    async def increment_validation_count(self):
        async with self._lock:
            self._validation_count += 1

    async def check_and_reset_validation_count(self, threshold: Optional[int]) -> bool:
        if not threshold:
            return False
        async with self._lock:
            if self._validation_count >= threshold:
                old_count = self._validation_count
                self._validation_count = 0
                logger.info(f"[→] [PIVOT-AFTER] Reached {old_count} validations → Triggering pivot")
                return True
            return False

#>DB
class database:
    def __init__(self, path: str=DEFAULT_CONFIG['CONN']['DBPATH'], config: Dict[str, Any]=DEFAULT_CONFIG):
        self.path = path
        self.config = config
        self.db: Optional[aiosqlite.Connection] = None
        self._lock = asyncio.Lock()

    async def init(self):
        dbp = Path(self.path).resolve()
        if not dbp.parent.exists():
            try:
                dbp.parent.mkdir(parents=True, exist_ok=True)
            except Exception as E:
                logger.critical(f"Failed to create database directory {dbp.parent}: {E}")
                sys.exit(1)

        if not os.access(dbp.parent, os.W_OK):
            logger.critical(f"Permission denied: Directory '{dbp.parent}' is not writable.")
            sys.exit(1)
        
        try:
            self.db = await aiosqlite.connect(str(dbp))
        except Exception as E:
            logger.critical(f"Fatal error: Unable to open database file at {dbp}: {E}")
            sys.exit(1)

        try:
            await self.db.execute("PRAGMA busy_timeout = 8000")
            await self.db.execute("PRAGMA synchronous = NORMAL")
            await self.db.execute("PRAGMA temp_store = MEMORY")
            await self.db.execute("PRAGMA mmap_size = 2147483648")
            await self.db.execute("PRAGMA cache_size = -256000")
        except Exception as e:
            logger.debug(f"Initial PRAGMA settings had issues: {e}")

        table_sql = """CREATE TABLE IF NOT EXISTS idx (
            ip TEXT,
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
            leak_dns INTEGER,
            verified INTEGER,
            time_check TEXT,
            via TEXT,
            PRIMARY KEY(ip, port, proto)
        )"""

        try:
            await self.db.execute(table_sql)
            # Create indexes on frequently queried columns
            for col in ["working", "country", "latency", "anonymity", "proto", "time_check", "via"]:
                index_name = f"idx_{col}_main"
                await self.db.execute(f"CREATE INDEX IF NOT EXISTS {index_name} ON idx({col})")
            await self.db.commit()
        except Exception as e:
            if "disk I/O error" in str(e).lower():
                await self.db.execute("PRAGMA journal_mode = MEMORY") 
                await self.db.execute(table_sql) 
                await self.db.execute("PRAGMA temp_store = MEMORY") 
                await self.db.commit()
            else:
                logger.critical(f"Critical database schema error: {e}")
                sys.exit(1) 

        try:
            await self.db.execute("PRAGMA journal_mode=WAL")
        except Exception as e:
            logger.debug(f"WAL mode not supported: {e}")

    async def qIndex(self, **filters: Any) -> List[proxy]:
        """Query the database with flexible filters."""
        query_filters = {}
        params: List[Any] = []

        if filters.get('ip'):
            query_filters['ip'] = filters['ip']
        if filters.get('country'):
            query_filters['country'] = filters['country']
        if filters.get('max_latency') is not None:
            query_filters['latency_max'] = filters['max_latency']
        if filters.get('proto'):
            query_filters['proto'] = filters['proto']
        if filters.get('anonymity'):
            query_filters['anonymity'] = filters['anonymity']
        if filters.get('via'):
            query_filters['via'] = filters['via']
        if filters.get('max_age_hours') is not None:
            cutoff_iso = (datetime.now(timezone.utc) - timedelta(hours=filters['max_age_hours'])).isoformat()
            query_filters['time_check_min'] = cutoff_iso

        base_q = """
            SELECT ip, proto, port, working, latency, anonymity, country, city, isp, org, asn, 
                   leak_dns, verified, time_check, via 
            FROM idx WHERE 1=1
        """

        for key, value in query_filters.items():
            if key == 'ip':
                base_q += " AND ip = ?"
                params.append(value)
            elif key == 'country':
                base_q += " AND country = ?"
                params.append(value)
            elif key == 'latency_max':
                base_q += " AND (latency IS NULL OR latency <= ?)"
                params.append(value)
            elif key == 'proto':
                base_q += " AND proto = ?"
                params.append(value)
            elif key == 'anonymity':
                base_q += " AND anonymity = ?"
                params.append(value)
            elif key == 'via':
                base_q += " AND via = ?"
                params.append(value)
            elif key == 'time_check_min':
                base_q += " AND time_check > ?"
                params.append(value)

        # Working/dead filtering
        if filters.get('include_dead', False):
            base_q += " AND working = 0"
        elif filters.get('include_working', True):
            base_q += " AND working = 1"

        async with self._lock:
            if not self.db:
                logger.error("Query attempted before database initialization.")
                return []

            try:
                async with self.db.execute(base_q, params) as cursor:
                    rows = await cursor.fetchall()
                    res: List[proxy] = []
                    for r in rows:
                        try:
                            p = proxy(proto=r[1], ip=r[0], port=r[2], via=r[14] or "LOCAL")
                            p.working = bool(r[3])
                            p.latency = r[4]
                            p.anonymity = r[5] or "Unknown"
                            p.country = r[6] or "??"
                            p.city = r[7] or "Unknown"
                            p.isp = r[8] or "Unknown"
                            p.org = r[9] or "Unknown"
                            p.asn = r[10] or "Unknown"
                            p.leak_dns = bool(r[11]) if r[11] is not None else False
                            p.verified = bool(r[12])
                            p.time_check = r[13]
                            res.append(p)
                        except Exception as e_parse:
                            logger.warning(f"Failed to parse DB row: {e_parse}")
                    return res
            except Exception as e_query:
                logger.error(f"Database query failed: {e_query}")
                return []

    async def add_many_async(self, db_connection: aiosqlite.Connection, proxies: List[tuple]):
        sql = (" INSERT OR REPLACE INTO idx (ip, proto, port, working, latency, anonymity, country, city, isp, org, asn, leak_dns, verified, time_check, via) "
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ")
        try:
            await db_connection.executemany(sql, proxies)
        except Exception as e_batch:
            logger.error(f"(add_many_async) Batch insertion failed: {e_batch}")


    async def bUpsert(self, proxies: List[proxy]):
        if not proxies:
            logger.debug("No proxies to upsert!")
            return
        
        logger.debug(f"(bUpsert) Bulk inserting {len(proxies)} proxy candidates...")
        async with self._lock:
            if not self.db:
                logger.error("Bulk Upsert attempted before database was initialized.")
                return
            try:
                to_insert: List[Tuple] = []
                for p in proxies:
                    data_item = (
                        p.ip, p.proto, p.port, int(p.working), p.latency, p.anonymity, p.country, p.city, p.isp, p.org, p.asn,
                        int(p.leak_dns), int(p.verified), p.time_check, p.via
                    )
                    to_insert.append(data_item)

                MAX_BATCH_SIZE = 500
                
                for i in range(0, len(to_insert), MAX_BATCH_SIZE):
                    batch = to_insert[i:i+MAX_BATCH_SIZE]
                    async with self.db.execute( "BEGIN IMMEDIATE"):
                        await self.add_many_async(self.db, batch)
                        await self.db.commit()
                    
            except asyncio.CancelledError:
                logger.debug("Batch Upsert was manually cancelled.")
            except Exception as e:
                if self.db: 
                    try: await self.db.rollback(); logger.error(f"(bUpsert) Rolled back due to {e}")
                    except RollbackException as rb_error: logger.critical(f"(bUpsert) Rollback also failed: {rb_error}!")
                else: logger.critical(f"(bUpsert) Critical error post-op: Database object missing? {e}")

    async def upsert(self, p: proxy):
        async with self._lock:
            if not self.db:
                logger.error("Upsert attempted before database was initialized.")
                return
            
            p.time_check = datetime.now(timezone.utc).isoformat()
            try:
                await self.db.execute("""
                INSERT OR REPLACE INTO idx (ip,proto,port,working,latency,anonymity,country,city,isp,org,asn,leak_dns,verified,time_check,via)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    p.ip, p.proto, p.port, int(p.working), p.latency, p.anonymity, p.country, p.city, p.isp, p.org, p.asn,
                      int(p.leak_dns), int(p.verified), p.time_check, p.via))
                await self.db.commit()
            except Exception as e_up:
                logger.error(f"DB Upsert failed for {p.ip}: {e_up}")
                if self.db:
                    try: await self.db.rollback()
                    except: logger.error("Rollback on upsert failed too.")

    async def statistics(self) -> Dict[str, Any]:
        async with self._lock:
            if not self.db:
                   logger.error("Statistics query attempted before database was initialized.")
                   return {}
            try:
                stats = { "total": 0, "working": 0, "dead": 0, "verified": 0,
                          "by_protocol": {}, "by_country": {}, "low_latency": 0, "high_latency": 0,
                          "by_anonymity": {"Elite": 0, "Anonymous": 0, "Transparent": 0, "Unknown": 0}, "recently_checked": 0 }
                async with self.db.execute("SELECT COUNT(*) FROM idx") as c: stats["total"] = (await c.fetchone() or [0])[0]
                async with self.db.execute("SELECT COUNT(*) FROM idx WHERE working = 1") as c: stats["working"] = (await c.fetchone() or [0])[0]
                async with self.db.execute("SELECT COUNT(*) FROM idx WHERE verified = 1") as c: stats["verified"] = (await c.fetchone() or [0])[0]
                async with self.db.execute("SELECT COUNT(*) FROM idx WHERE working = 0 AND time_check IS NOT NULL") as c: stats["dead"] = (await c.fetchone() or [0])[0]
                async with self.db.execute("SELECT COUNT(*) FROM idx WHERE latency <= 2.0") as c: stats["low_latency"] = (await c.fetchone() or [0])[0]
                async with self.db.execute("SELECT COUNT(*) FROM idx WHERE latency > 2.0 AND latency IS NOT NULL") as c: stats["high_latency"] = (await c.fetchone() or [0])[0]
                async with self.db.execute("SELECT anonymity, COUNT(*) FROM idx GROUP BY anonymity") as c:
                    anon_rows = await c.fetchall()
                    for k, v in anon_rows: stats["by_anonymity"][k or "Unknown"] = v
                async with self.db.execute("SELECT proto, COUNT(*) FROM idx GROUP BY proto") as c:
                    prot_rows = await c.fetchall()
                    stats["by_protocol"] = {k: v for k, v in prot_rows}
                    
                async with self.db.execute("SELECT country, COUNT(*) FROM idx GROUP BY country ORDER BY COUNT(*) DESC LIMIT 5") as c:
                    country_rows = await c.fetchall()
                    stats["by_country"] = {k if k else "Unknown": v for k, v in country_rows}
                cutoff_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
                async with self.db.execute("SELECT COUNT(*) FROM idx WHERE time_check > ?", (cutoff_time,)) as c:
                    stats["recently_checked"] = (await c.fetchone() or [0])[0]
                if "total" in stats and stats["total"] > 0:
                    for k in ["working", "verified", "dead"]:
                        if k in stats: stats[f"{k}_pct"] = round(100 * stats[k] / stats["total"], 2)
                return stats
            except Exception as e_stats:
               logger.error(f"DB Statistics gathering failed: {e_stats}")
               return {"error": str(e_stats)}

    async def export_to_json(self, output_path: str, **filters: Any) -> bool:
        """Export filtered database contents to a JSON file."""
        try:
            results = await self.qIndex(**filters)
            if not results:
                logger.warning("No entries matched the export filters.")
                return False
            
            pdata = [p.format_json() for p in results]
            export = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": __version__,
                "author": __author__,
                "count": len(pdata),
                "filters": {k: v for k, v in filters.items() if v is not None},
                "index": pdata
            }
            
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(export, indent=2, ensure_ascii=False))
            logger.info(f"→ Exported {len(pdata)} proxies to `{path}`")
            return True
        except PermissionError:
            logger.error(f"Permission denied writing to `{output_path}`")
            return False
        except Exception as e:
            logger.error(f"DB JSON export failed: {e}")
            return False

    async def import_from_json(self, input_path: str) -> int:
        """Import proxy metadata from a JSON file into the database.
        
        Supports formats:
        - Plain list of proxy dicts
        - Dict with 'index', 'proxies', or 'data' key
        """
        try:
            path = Path(input_path)
            if not path.exists():
                logger.error(f"Import file not found: {input_path}")
                return 0
            
            raw = json.loads(path.read_text(encoding='utf-8'))
            
            # Normalize: handle both list and dict-with-index formats
            if isinstance(raw, list):
                entries = raw
            elif isinstance(raw, dict):
                entries = (
                    raw.get("index") 
                    or raw.get("proxies") 
                    or raw.get("data") 
                    or raw.get("results")
                    or []
                )
            else:
                logger.error(f"Unexpected JSON structure in {input_path}")
                return 0
            
            if not isinstance(entries, list):
                entries = [entries]
            
            imported_proxies: List[proxy] = []
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                if not all(k in entry for k in ("ip", "port", "proto")):
                    continue
                try:
                    p = proxy(
                        entry["proto"],
                        entry["ip"],
                        int(entry["port"]),
                        via=f"DB_IMPORT({input_path})"
                    )
                    # Restore metadata fields (using new attribute names for ngf016)
                    p.country = entry.get("country", p.country)
                    p.city = entry.get("city", p.city)
                    p.isp = entry.get("isp", p.isp)
                    p.org = entry.get("org", p.org)
                    p.asn = entry.get("asn", p.asn)
                    p.verified = bool(entry.get("verified", False))
                    p.working = bool(entry.get("working", False))
                    p.latency = entry.get("latency")
                    p.time_check = entry.get("time_check") or entry.get("timeCheck")
                    p.anonymity = entry.get("anonymity", "Unknown")
                    p.leak_dns = bool(entry.get("leak_dns", False))
                    imported_proxies.append(p)
                except Exception as e:
                    logger.warning(f"(import_from_json) Failed to parse entry: {e}")
            
            if imported_proxies:
                await self.bUpsert(imported_proxies)
                logger.info(f"✓ Imported {len(imported_proxies)} proxies from `{input_path}`")
            
            return len(imported_proxies)
        except Exception as e:
            logger.error(f"Import from JSON `{input_path}` failed: {e}")
            return 0

    async def get_recent_working_candidates(self, types: List[str], min_age_minutes: int = 5) -> List[proxy]:
        cutoff_iso = (datetime.now(timezone.utc) - timedelta(minutes=min_age_minutes)).isoformat()
        proxies = await self.qIndex(include_working=True, time_check_min=cutoff_iso)
        key_func = lambda x: (x.time_check or '', x.country) if 'country' in x.__dict__ else x.time_check or ''
        try:
            proxies.sort(key=key_func, reverse=True)
        except TypeError:
            proxies.sort(key=lambda x: x.time_check or '', reverse=True)
        return proxies

    async def clear(self):
        logger.info(f"Clearing ALL data from database {self.path}...")
        async with self._lock:
            if not self.db: return
            try:
                await self.db.execute("DELETE FROM idx")
                await self.db.commit()
                await self.db.execute("VACUUM")
                await self.db.commit()
            except Exception as e_clr:
                logger.error(f"Database clear failed: {e_clr}")

    async def close(self):
        if self.db:
            await self.db.close()
            self.db = None
#>Stats
class StatsReporter:
    def __init__(self):
        self.metrics = {
            "start_time": time.time(),
            "network_requests": 0,
            "network_errors": 0,
            "validations_sent": 0,
            "successful_validations": 0,
            "failed_validations": 0,
            "proxies_returned": 0,
        }

    def get_runtime_summary(self):
        end_time = time.time()
        metrics = self.metrics.copy()
        metrics["runtime_seconds"] = round(end_time - self.metrics["start_time"], 2)
        rt = metrics["runtime_seconds"]
        if rt > 0:
            metrics["req_per_sec"] = round(metrics["network_requests"] / rt, 2)
            metrics["vld_req_per_sec"] = round(metrics["validations_sent"] / rt, 2)
            total_vld = (metrics["successful_validations"] + metrics["failed_validations"])
            success_rate = (100 * metrics["successful_validations"] / total_vld) if total_vld > 0 else 0
            metrics["success_rate_%"] = round(success_rate, 2)
        return metrics

    async def print_rich_summary(self, console: Console):
        stats_dict = self.get_runtime_summary()
        table = Table(title="Execution Summary", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="dim", width=25)
        table.add_column("Value", justify="right", style="bold white", width=15) 
        table.add_row("Runtime (seconds)", f"{stats_dict['runtime_seconds']:.2f}")
        table.add_row("Net Req Made", str(stats_dict["network_requests"]))
        table.add_row("Net Errors", str(stats_dict["network_errors"]))
        table.add_row("Validations Sent", str(stats_dict["validations_sent"]))
        table.add_row("Successful Vlds", str(stats_dict["successful_validations"]))
        table.add_row("Success Rate (%)", f"{stats_dict['success_rate_%']:.2f}")
        table.add_row("Proxies Returned", str(stats_dict["proxies_returned"]))
        console.print(table)

_stats_reporter = None # Global instance

#>NGF
class NGFetcher:
    def __init__(self, args: argparse.Namespace, config: Dict[str, Any]):
        self.args = args
        self.config = config
        # Database
        db_path = Path(self.args.db_path) / self.args.db_fname
        self.db = database(str(db_path), config=config)
        # Sessions
        self.h_session = requests.AsyncSession(impersonate="chrome110")
        self.v_session = requests.AsyncSession(impersonate="chrome110")
        self.h_session.headers["User-Agent"] = random.choice(self.config["USER_AGENTS"])
        # Semaphores
        self.concurrent_threads_sem = asyncio.Semaphore(self.config['CONN']['CONCURRENCY_LIMIT'])
        self.network_gather_sem = asyncio.Semaphore(self.config['CONN']['NETWORK_CONCURRENCY_LIMIT'])
        self.verification_in_flight_sem = asyncio.Semaphore(30)
        # Async
        self.p_est_lock = asyncio.Lock()
        self.term_event = asyncio.Event()
        # Pivot Management
        self.pivot_mgr = PivotManager()
        self.pref_countries = {c.strip().upper() for c in (self.args.country_filter or "").split(',') if c.strip()}
        self.excl_countries = {c.strip().upper() for c in (self.args.exclude_country or "").split(',') if c.strip()}
        # Host Info
        self.host_address = None
        self.host_country_code = None
        self.working_proxies = []


    async def resolve_hosts_public_info(self):
        logger.debug("Retrieving... (resolve_host_info)")
        try:
            url = "http://ip-api.com/json/?fields=status,query,countryCode,city,isp,org,as"
            async with self.verification_in_flight_sem: 
                response = await self.h_session.get(url, timeout=self.config['CONN']['TIMEOUT'] + 2)
            global _stats_reporter
            if _stats_reporter: _stats_reporter.metrics["network_requests"] += 1
            if response.status_code == 200 and response.content:
                data = response.json()
                self.host_address = data.get("query", data.get("ip", data.get("origin")))
                self.host_country_code = data.get("countryCode")
                logger.info(f"Host IP: `{self.host_address}` | Country: `{self.host_country_code or 'N/A'}`")
                return True
            else:
                logger.warning(f"Failed. Status: {response.status_code}.")
                return False 
        except Exception as e:
            if _stats_reporter: _stats_reporter.metrics["network_errors"] += 1
            logger.warning(f"Unexpected error: {e.__class__.__name__}: {e}")
        return False


    async def establish_pivot_proxy(self) -> bool:
        """Establish or rotate a pivot proxy with clear logging and better fallback logic."""
        async with self.p_est_lock:
            if await self.pivot_mgr.get_pivot_url():
                logger.debug("Pivot already exists.")
                return True

            logger.info("[←→] Establishing new pivot proxy...")

            # Manual pivot from --pivot argument
            if self.args.pivot:
                manual_urls = [u.strip() for u in self.args.pivot.split(",") if u.strip()]
                logger.info(f"Testing {len(manual_urls)} manual pivot(s)...")
                for url_str in manual_urls:
                    try:
                        parsed = urlparse(url_str if "://" in url_str else f"http://{url_str}")
                        proto = parsed.scheme.lower() or "http"
                        ip = parsed.hostname
                        port = parsed.port
                        if not ip or not port or proto not in ["http", "https", "socks5"]:
                            logger.warning(f"Invalid manual pivot: {url_str}")
                            continue

                        man_p = proxy(proto, ip, int(port), via="ARG_PIVOT")
                        if self._should_skip_proxy_pre_checks(man_p):
                            continue

                        logger.info(f"Testing manual pivot: {man_p.short()}")
                        try:
                            success = await asyncio.wait_for(
                                self.perform_proxy_test(man_p, is_pivot=True, for_audit=True, update_db=False),
                                timeout=15.0
                            )
                            if success:
                                await self.pivot_mgr.set_pivot(man_p)
                                CONSOLE.print(f"[bold green]✓[/] Manual pivot established: {man_p.format_url()}")
                                logger.info(f"✓ Manual pivot established: {man_p.format_url()}")
                                return True
                        except asyncio.TimeoutError:
                            logger.warning(f"Manual pivot test timeout: {man_p.short()}")
                        except Exception as e:
                            logger.warning(f"Manual pivot failed: {url_str} - {e}")
                    except Exception as e:
                        logger.warning(f"Error parsing manual pivot {url_str}: {e}")

            # Try recent DB candidates
            pivot_protocols = ["http", "https"] if self.args.pivot_http_only else self.args.type
            recent_seeds = await self.db.get_recent_working_candidates(
                types=pivot_protocols, min_age_minutes=3
            )
            
            logger.info(f"Testing {min(32, len(recent_seeds))} recent DB candidates for pivot...")
            for pot_seed_pivot in recent_seeds[:32]:
                if await self.pivot_mgr.is_blacklisted(pot_seed_pivot.ip):
                    continue
                if self._should_skip_proxy_pre_checks(pot_seed_pivot):
                    continue

                logger.debug(f"Testing DB seed: {pot_seed_pivot.short()}")
                try:
                    success = await asyncio.wait_for(
                        self.perform_proxy_test(pot_seed_pivot, is_pivot=True, for_audit=True, update_db=False),
                        timeout=15.0
                    )
                    if success:
                        await self.pivot_mgr.set_pivot(pot_seed_pivot)
                        logger.debug(f"[✔] DB candidate promoted to pivot: {pot_seed_pivot.format_url()}")
                        return True
                except asyncio.TimeoutError:
                    logger.warning(f"Pivot test timeout for DB seed: {pot_seed_pivot.short()}")
                    await self.pivot_mgr.blacklist_ip(pot_seed_pivot.ip, 180)
                except Exception as e:
                    logger.debug(f"DB seed test failed: {pot_seed_pivot.short()} - {e}")

            # Bootstrap from sources if needed
            bootstrap_urls = []
            for p_type in pivot_protocols:
                if p_type.lower() in self.config.get("SOURCE_URLS", {}):
                    urls = self.config["SOURCE_URLS"][p_type.lower()]
                    bootstrap_urls.extend(u for u in urls[:2])

            if bootstrap_urls:
                logger.info(f"Fetching bootstrap candidates from {len(bootstrap_urls)} sources...")
                try:
                    bootstrap_candidates = await asyncio.wait_for(
                        self.fetch_sources_from_urls(
                            urls=bootstrap_urls, 
                            using_pivot=False
                        ),
                        timeout=40.0
                    )
                    
                    logger.info(f"Testing {min(20, len(bootstrap_candidates))} bootstrap candidates...")
                    for bp in bootstrap_candidates[:20]:
                        if await self.pivot_mgr.is_blacklisted(bp.ip):
                            continue
                        logger.debug(f"Testing bootstrap: {bp.short()}")
                        try:
                            success = await asyncio.wait_for(
                                self.perform_proxy_test(bp, is_pivot=True, for_audit=True, update_db=False),
                                timeout=15.0
                            )
                            if success:
                                await self.pivot_mgr.set_pivot(bp)
                                logger.success(f"[✔] Bootstrap pivot established: {bp.format_url()}")
                                return True
                        except asyncio.TimeoutError:
                            logger.warning(f"Bootstrap pivot timeout: {bp.short()}")
                        except Exception as e:
                            logger.debug(f"Bootstrap test failed: {e}")
                except asyncio.TimeoutError:
                    logger.warning("Bootstrap source fetching timed out.")
                except Exception as e:
                    logger.error(f"Bootstrap failed: {e}")

            logger.error("[!] Failed to establish any pivot proxy.")
            return False

    async def get_pivot_url(self, wait_if_missing: bool = False) -> Optional[str]:
        u = await self.pivot_mgr.get_pivot_url()
        if u: return u
        if wait_if_missing or (self.args.opsec and not self.host_address):
            logger.debug("No prior pivot found. Mode: opsec={}, proxy_only={}, req_wait={}".format(
                self.args.opsec, self.args.proxy_only, wait_if_missing))
            if self.args.proxy_only or await self.establish_pivot_proxy():
                return await self.pivot_mgr.get_pivot_url()
        return None

    async def perform_proxy_test(self, p: proxy, is_pivot: bool = False, for_audit: bool = False, update_db: bool = True) -> bool:
        p_ip_during_check = p.ip
        test_target = random.choice(self.config['VALIDATION_TARGETS'])
        
        # === OPSEC + PIVOT FIX ===
        # When testing the pivot itself, we must test it DIRECTLY (no chaining)
        if is_pivot:
            proxy_to_use = p.format_url()
            pivot_url_to_use = None
        else:
            pivot_url_to_use = await self.get_pivot_url(wait_if_missing=False)
            proxy_to_use = pivot_url_to_use if pivot_url_to_use else p.format_url()
        # ======================================

        global _stats_reporter
        if _stats_reporter and not is_pivot:
            _stats_reporter.metrics["validations_sent"] += 1

        async with self.concurrent_threads_sem:
            try:
                ua_check = random.choice(self.config["USER_AGENTS"])
                
                # Debug line
                logger.debug(f"Testing {p.short()} | is_pivot={is_pivot} | routed_via_pivot={bool(pivot_url_to_use)}")

                start_val_time = time.time()
                async with self.verification_in_flight_sem:
                    val_response = await self.v_session.get(
                        test_target, 
                        proxy=proxy_to_use,                    # ← Fixed
                        headers={"User-Agent": ua_check}, 
                        timeout=self.config['CONN']['TIMEOUT']
                    )
                latency_val = round(time.time() - start_val_time, 2)

                if val_response.status_code == 200 and val_response.content:
                    data = val_response.json()
                    reported_ip = data.get("query") or data.get("ip") or data.get("origin", "")
                    if reported_ip == p_ip_during_check:
                        p.anonymity = "Elite"
                    else:
                        if self.host_address and reported_ip != self.host_address:
                            p.anonymity = "Anonymous"
                        else:
                            p.anonymity = "Transparent"

                    p.latency = latency_val
                    p.working = True
                    p.verified = True
                    p.time_check = datetime.now(timezone.utc).isoformat()
                    p.country = data.get("countryCode", p.country)
                    p.city = data.get("city", p.city)
                    p.isp = data.get("isp", p.isp)
                    p.org = data.get("org", p.org)
                    p.asn = data.get("as", p.asn)

                    if _stats_reporter and not is_pivot:
                        _stats_reporter.metrics["successful_validations"] += 1

                    # Extra audit via pivot (only if not testing pivot itself)
                    if not self.args.no_audit_via_pivot and pivot_url_to_use and not is_pivot:
                        try:
                            audit_url = f"http://ip-api.com/json/{p.ip}?fields=status,countryCode,city,isp,org,as"
                            async with self.verification_in_flight_sem:
                                audit_resp = await self.h_session.get(
                                    audit_url, 
                                    proxy=pivot_url_to_use, 
                                    timeout=self.config['CONN']['TIMEOUT']
                                )
                            if _stats_reporter:
                                _stats_reporter.metrics["network_requests"] += 1
                            if audit_resp.status_code == 200 and audit_resp.content:
                                audit_data = audit_resp.json()
                                p.country = audit_data.get("countryCode", p.country)
                                p.city = audit_data.get("city", p.city)
                                p.isp = audit_data.get("isp", p.isp)
                                p.org = audit_data.get("org", p.org)
                                p.asn = audit_data.get("as", p.asn)
                        except Exception:
                            pass 

                    # DNS Leak Check (skip if testing pivot)
                    if not self.args.no_dns_leak_check and not is_pivot:
                        try:
                            dns_leak_start = time.time()
                            async with self.verification_in_flight_sem:
                                dns_resp = await self.v_session.get(
                                    "http://edns.ip-api.com/json", 
                                    proxy=proxy_to_use,          # ← Also fixed
                                    timeout=8
                                )
                            if _stats_reporter:
                                _stats_reporter.metrics["network_requests"] += 1
                            if dns_resp.status_code == 200 and dns_resp.content:
                                dns_data = dns_resp.json()
                                dns_geo_block = dns_data.get("dns", {}).get("geo", "").upper() or "UNKNOWN"
                                if dns_geo_block != "UNKNOWN":
                                    if self.host_country_code and p.country != "??":
                                        p.leak_dns = self.host_country_code in dns_geo_block and p.country != self.host_country_code
                                        if p.leak_dns:
                                            logger.warning(f"DNS leak detected for {p.ip}!")
                                        p.dns_leak_test_latency = round(time.time() - dns_leak_start, 2)
                        except Exception as e_dns:
                            if _stats_reporter:
                                _stats_reporter.metrics["network_errors"] += 1
                    else:
                        p.leak_dns = False
                    
                    if update_db:
                        await self.db.upsert(p)
                    return True
                else:
                    p.working, p.verified, p.time_check = False, False, datetime.now(timezone.utc).isoformat()
                    if update_db:
                        await self.db.upsert(p)
                    if _stats_reporter and not is_pivot:
                        _stats_reporter.metrics["failed_validations"] += 1
                    
            except asyncio.TimeoutError:
                logger.warning(f"Timeout testing proxy {p.short()}")
                if _stats_reporter:
                    _stats_reporter.metrics["network_errors"] += 1
            except Exception as e_main:
                if _stats_reporter:
                    _stats_reporter.metrics["network_errors"] += 1
                logger.debug(f"Error testing {p.short()}: {e_main.__class__.__name__}")

            # Final failure path
            p.working = False
            p.verified = False
            p.latency = None
            p.time_check = datetime.now(timezone.utc).isoformat()
            p.anonymity = "Unknown"
            p.country = "??"
            p.city = "Unknown"
            if update_db:
                await self.db.upsert(p)
            if _stats_reporter and not is_pivot:
                _stats_reporter.metrics["failed_validations"] += 1
            return False

    async def check_pivot_health_and_rotate(self):
        """Fixed: Now works for --pivot-after too"""
        try:
            while not self.term_event.is_set():
                sleep_time = 30  # tighter check

                currently_required_by_mode = self.args.opsec or self.args.proxy_only
                should_require_pivot = await self.pivot_mgr.check_and_reset_validation_count(
                    getattr(self.args, 'pivot_after', None)
                )

                have_pivot = bool(await self.pivot_mgr.get_pivot())

                if not have_pivot and (currently_required_by_mode or should_require_pivot):
                    if should_require_pivot:
                        logger.info("[!][→] --pivot-after threshold hit. Establishing pivot...")
                    else:
                        logger.info("[→] Establishing required pivot...")
                    await self.establish_pivot_proxy()

                elif have_pivot:
                    # Health check
                    current_pivot_obj = await self.pivot_mgr.get_pivot()
                    if current_pivot_obj:
                        try:
                            test_url = random.choice(DEFAULT_CONFIG['VALIDATION_TARGETS'])
                            test_resp = await self.h_session.get(test_url, proxy=current_pivot_obj.format_url(), timeout=5)
                            if _stats_reporter:
                                _stats_reporter.metrics["network_requests"] += 1
                            if test_resp and test_resp.status_code not in [200, 401, 403]:
                                logger.warning(f"← Pivot failed health check: {current_pivot_obj.short()}. Rotating...")
                                await self.pivot_mgr.blacklist_ip(current_pivot_obj.ip, 300)
                                await self.pivot_mgr.clear_pivot()
                                if currently_required_by_mode or should_require_pivot:
                                    await self.establish_pivot_proxy()
                        except Exception:
                            if _stats_reporter: _stats_reporter.metrics["network_errors"] += 1

                # Usage rotation
                current_pivot = await self.pivot_mgr.get_pivot()
                if current_pivot:
                    should_rotate = await self.pivot_mgr.increment_usage(self.args.pivot_limit_if_set)
                    if should_rotate:
                        logger.info(f"[→] Pivot usage limit reached → Blacklisting & rotating {current_pivot.short()}")
                        await self.pivot_mgr.blacklist_ip(current_pivot.ip, 600)
                        await self.pivot_mgr.clear_pivot()

                try:
                    await asyncio.wait_for(self.term_event.wait(), timeout=sleep_time)
                except asyncio.TimeoutError:
                    continue
                else:
                    break
        except asyncio.CancelledError:
            logger.debug("← Pivot health task cancelled.")
            raise
        except Exception as e:
            logger.error(f"Pivot health error: {e}")
        finally:
            logger.debug("Pivot health task exiting.")

    def _should_skip_proxy_pre_checks(self, p: proxy) -> bool:
        if self.args.skip_all_dead and p.working == False and p.time_check: 
            return True 
        if self.args.skip_recently_validated and p.verified and p.time_check:
            try:
                last_check = datetime.fromisoformat(p.time_check) 
                age_in_seconds = (datetime.now(timezone.utc) - last_check).total_seconds()
                hours_thresh = getattr(self.args, 'skip_recency_hours', 1) * 3600
                if age_in_seconds < hours_thresh:
                    return True
            except (ValueError, TypeError, AttributeError):
                pass
        return False

    async def _load_remote_json(self, url: str) -> List[proxy]:
        """Download and parse remote JSON, supporting .json, .gz, and .tar.gz"""
        import tempfile
        import tarfile
        import gzip
        from urllib.parse import urlparse

        try:
            async with self.network_gather_sem:
                pivot_url = await self.get_pivot_url(wait_if_missing=(self.args.opsec or self.args.proxy_only))
                
                response = await self.h_session.get(
                    url, 
                    proxy=pivot_url,
                    timeout=90
                )
                
                if response.status_code != 200:
                    logger.error(f"Failed to download remote file: HTTP {response.status_code}")
                    return []

                content = response.content
                filename = urlparse(url).path.split('/')[-1].lower()

                with tempfile.TemporaryDirectory() as tmpdir:
                    tmp_path = Path(tmpdir)

                    if filename.endswith(('.tar.gz', '.tgz')):
                        tar_path = tmp_path / "data.tar.gz"
                        tar_path.write_bytes(content)
                        with tarfile.open(tar_path, 'r:gz') as tar:
                            tar.extractall(tmp_path)
                        json_files = list(tmp_path.rglob("*.json"))
                    elif filename.endswith('.gz'):
                        gz_path = tmp_path / "data.gz"
                        gz_path.write_bytes(content)
                        json_path = tmp_path / "data.json"
                        with gzip.open(gz_path, 'rb') as f_in:
                            json_path.write_bytes(f_in.read())
                        json_files = [json_path]
                    else:
                        # Raw JSON
                        json_path = tmp_path / "data.json"
                        json_path.write_bytes(content)
                        json_files = [json_path]

                    if not json_files:
                        logger.warning("No .json file found in the downloaded archive.")
                        return []

                    # Parse the first JSON file
                    data = json.loads(json_files[0].read_text(encoding='utf-8'))
                    
                    proxies = []
                    # Flexible JSON structure handling
                    if isinstance(data, list):
                        items = data
                    elif isinstance(data, dict):
                        items = data.get('proxies') or data.get('data') or data.get('results') or list(data.values())
                    else:
                        items = []

                    for item in items:
                        try:
                            if isinstance(item, str):
                                # e.g. "socks5://1.2.3.4:1080"
                                if '://' in item:
                                    proto_part, addr = item.split('://', 1)
                                    ip, port = addr.rsplit(':', 1)
                                    p = proxy(proto_part.strip().lower(), ip.strip(), int(port))
                                    proxies.append(p)
                            elif isinstance(item, dict):
                                proto = (item.get('proto') or item.get('type') or item.get('protocol') or 'socks5').lower()
                                ip = item.get('ip') or item.get('server') or item.get('host')
                                port = item.get('port')
                                if ip and port:
                                    p = proxy(str(proto), str(ip), int(port))
                                    p.country = item.get('country', p.country)
                                    p.anonymity = item.get('anonymity', p.anonymity)
                                    proxies.append(p)
                        except Exception:
                            continue

                    logger.info(f"Successfully parsed {len(proxies)} proxies from remote JSON")
                    return proxies

        except Exception as e:
            logger.error(f"Failed to load remote JSON from {url}: {e}")
            return []

    async def find_candidate_proxies(self, types_needed: List[str], apply_smart_filters: bool = True) -> List[proxy]:
        candidates: List[proxy] = []
        db_candidates_full = []
        for t in types_needed:
            db_candidates_full.extend(await self.db.qIndex(
                include_working=True,
                include_dead=not self.args.skip_all_dead,
                max_age_hours=getattr(self.args, 'db_fetch_max_age', None),
                proto=t
            ))
        
        # Deduplicate
        seen_ids = set()
        candidates_unique = []
        for cand_db in db_candidates_full:
            proxy_key = (cand_db.ip, cand_db.port, cand_db.proto)
            if proxy_key not in seen_ids:
                candidates_unique.append(cand_db)
                seen_ids.add(proxy_key)
        candidates.extend(candidates_unique)
        if apply_smart_filters:
            num_before_filter = len(candidates)
            initial_pref = self.pref_countries
            initial_excl = self.excl_countries
            filtered_cands = []
            
            for c in candidates:
                if initial_excl and c.country and c.country.upper() in initial_excl:
                    continue
                if (not initial_pref) or (initial_pref and c.country and c.country.upper() in initial_pref):
                    filtered_cands.append(c)
            
            removed_count = num_before_filter - len(filtered_cands)
            if removed_count > 0:
                logger.info(f"Smart filter removed {removed_count} candidates.")
            candidates = filtered_cands
        if getattr(self.args, 'json_remote_load', False) and getattr(self.args, 'json_remote_url', None):
            logger.info(f"→ Loading remote JSON from: {self.args.json_remote_url}")
            remote_proxies = await self._load_remote_json(self.args.json_remote_url)
            
            if remote_proxies:
                new_uniques = 0
                seen_db_keys = {(c.ip, c.port, c.proto) for c in candidates}
                for rp in remote_proxies:
                    key = (rp.ip, rp.port, rp.proto)
                    if key not in seen_db_keys:
                        candidates.append(rp)
                        seen_db_keys.add(key)
                        new_uniques += 1
                logger.info(f"Ingested {new_uniques} proxies from remote JSON.")
            return candidates  # Early return when using remote JSON mode

        if self.args.fetch_new_sources or (not candidates and not (self.args.update_json or self.args.validate_json or self.args.json_remote_load)):
            urls_to_fetch = set()
            for t in types_needed:
                t_lower = t.lower()
                if t_lower in self.config.get('SOURCE_URLS', {}):
                    source_count = getattr(self.args, 'max_sources_per_type', 999)
                    for url in self.config['SOURCE_URLS'][t_lower][:int(source_count)]:
                        urls_to_fetch.add(url)
            
            new_candidates = await self.fetch_sources_from_urls(
                urls=list(urls_to_fetch), 
                using_pivot=(self.args.opsec or self.args.proxy_only)
            )

            new_uniques = 0
            seen_db_keys = {(c.ip, c.port, c.proto) for c in candidates}
            for nc in new_candidates:
                nc_key = (nc.ip, nc.port, nc.proto)
                if nc_key not in seen_db_keys:
                    candidates.append(nc)
                    seen_db_keys.add(nc_key)
                    new_uniques += 1
            logger.info(f"Ingested {new_uniques} truly unique new candidates.")
        
        to_validate = []
        skipped_pre = 0
        for p in candidates:
            if not self._should_skip_proxy_pre_checks(p):
                to_validate.append(p)
            else:
                skipped_pre += 1
        if skipped_pre:
            logger.info(f"Pre-filter skipped {skipped_pre} proxies.")
        
        return to_validate

    async def _load_json_raw(self, source: str) -> Any:
        """Load JSON data from a local path or remote URL."""
        if source.startswith(("http://", "https://")):
            logger.info(f"Loading JSON from remote URL: {source}")
            try:
                async with self.network_gather_sem:
                    pivot_url = None
                    if self.args.opsec or self.args.proxy_only:
                        pivot_url = await self.get_pivot_url(wait_if_missing=True)
                    resp = await self.h_session.get(source, proxy=pivot_url, timeout=25)
                    if resp.status_code != 200:
                        raise ValueError(f"Remote JSON fetch failed with status {resp.status_code}")
                    if _stats_reporter:
                        _stats_reporter.metrics["network_requests"] += 1
                    return json.loads(resp.text)
            except Exception as e:
                raise RuntimeError(f"Failed to load remote JSON from `{source}`: {e}")
        
        p_path = Path(source)
        if not p_path.exists():
            raise FileNotFoundError(f"JSON source not found: {source}")
        try:
            return json.loads(p_path.read_text(encoding='utf-8'))
        except Exception as e:
            raise RuntimeError(f"Failed to load JSON from `{source}`: {e}")

    async def load_json_proxies(self, source: str) -> List[proxy]:
        """Load and normalize proxy list from a JSON file or remote URL (plain .json only for remote)."""
        raw = await self._load_json_raw(source)
        proxies: List[proxy] = []
        
        entries: List[Dict] = []
        if isinstance(raw, list):
            entries = raw
        elif isinstance(raw, dict):
            entries = (
                raw.get("index")
                or raw.get("proxies")
                or raw.get("data")
                or raw.get("results")
                or []
            )
        
        if not isinstance(entries, list):
            entries = [entries]
        
        seen = set()
        for item in entries:
            if not isinstance(item, dict):
                continue
            proto = str(item.get("proto", "")).lower()
            ip = item.get("ip")
            port = item.get("port")
            if not proto or not ip or not port:
                continue
            try:
                port = int(port)
                if not (1 <= port <= 65535):
                    continue
            except (ValueError, TypeError):
                continue
            
            # Deduplicate
            key = (str(ip), port, proto)
            if key in seen:
                continue
            seen.add(key)
            
            try:
                p = proxy(proto, str(ip), port, via=f"JSON_LOAD({source})")
                p.country = item.get("country", p.country)
                p.city = item.get("city", p.city)
                p.isp = item.get("isp", p.isp)
                p.org = item.get("org", p.org)
                p.anonymity = item.get("anonymity", p.anonymity)
                proxies.append(p)
            except ValueError:
                continue
        
        logger.info(f"Loaded {len(proxies)} proxies from JSON source: {source}")
        return proxies

    async def fetch_sources_from_urls(self, urls: List[str], using_pivot: bool) -> List[proxy]:
        regex_compiled = re.compile(IP_PORT_REGEX_PATTERN) 
        collected = []
        
        def infer_protocol(u: str) -> str:
            u_lower = u.lower()
            if "socks5" in u_lower: 
                return "socks5"
            elif "socks4" in u_lower: 
                return "socks4"
            elif "https" in u_lower: 
                return "https"
            else: 
                return "http"

        logger.debug(f"Gathering from {len(urls)} URLs, using pivot: {using_pivot}")

        async def fetch_single(url: str) -> List[proxy]:
            async with self.network_gather_sem:
                if self.term_event.is_set():
                    return []
                try:
                    pivot_url = await self.get_pivot_url(wait_if_missing=using_pivot) if using_pivot else None
                    ua = random.choice(self.config["USER_AGENTS"])
                    headers = {"User-Agent":ua}
                    response = await self.h_session.get(
                        url, 
                        proxy=pivot_url,
                        headers=headers,
                        timeout=25)
                    if _stats_reporter: _stats_reporter.metrics["network_requests"] += 1
                    cur_pivot = await self.pivot_mgr.get_pivot()
                    if using_pivot and cur_pivot:
                        should_rotate = await self.pivot_mgr.increment_usage(self.args.pivot_limit_if_set)
                        if should_rotate:
                            logger.info("Pivot rotation triggered during source fetching.")
                    if response.status_code != 200:
                        if _stats_reporter: _stats_reporter.metrics["network_errors"] += 1
                        logger.warning(f"Failed to fetch {url} (Status: {response.status_code}).")
                        return []
                    content = response.text
                    proto_guess = infer_protocol(url) 
                    found_here = set() 
                    local_proxies = []
                    for match in regex_compiled.finditer(content):
                        ip_port_str = match.group(0) 
                        try:
                             ip, port_str = ip_port_str.rsplit(":", 1) 
                             port = int(port_str)
                             if 1 <= port <= 65535 and re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
                                  unique_key = (ip, port, proto_guess)
                                  if unique_key not in found_here:
                                       try: 
                                           p = proxy(proto_guess, ip, port, via=url)
                                           found_here.add(unique_key)
                                           local_proxies.append(p) 
                                       except ValueError as ve:
                                            pass
                        except (ValueError, AttributeError):
                            pass
                    
                    if self.args.load_source_counts: 
                        pass
                    return local_proxies 
                except Exception as e:
                    if _stats_reporter: _stats_reporter.metrics["network_errors"] += 1
                return [] 
        tasks = [fetch_single(u) for u in urls]
        all_results = await asyncio.gather(*tasks, return_exceptions=True)

        all_proxies = []
        for i, result in enumerate(all_results):
            if isinstance(result, Exception):
                logger.error(f"Failed to fetch from URL {urls[i]}: {result.__class__.__name__}: {result}")
                continue
            all_proxies.extend(result)

        final_unique_proxies = []
        seen_final = set()
        for px in all_proxies:
            key = (px.ip, px.port, px.proto)
            if key not in seen_final:
               final_unique_proxies.append(px)
               seen_final.add(key)

        return final_unique_proxies


    async def perform_proxy_test(self, p: proxy, is_pivot: bool = False, for_audit: bool = False, update_db: bool = True) -> bool:
        if is_pivot:
            pivot_url_to_use = None
        else:
            pivot_url_to_use = await self.get_pivot_url(wait_if_missing=False)
        
        p_ip_during_check = p.ip
        test_target = random.choice(self.config['VALIDATION_TARGETS'])
        
        global _stats_reporter
        if _stats_reporter and not is_pivot:
            _stats_reporter.metrics["validations_sent"] += 1

        async with self.concurrent_threads_sem:
            try:
                ua_check = random.choice(self.config["USER_AGENTS"])
                pivot_url_to_use = await self.get_pivot_url(wait_if_missing=False)
                logger.debug(f"Testing {p.short()} via pivot: [{bool(pivot_url_to_use)}]:{str(pivot_url_to_use) if pivot_url_to_use else "<null>"}")
                if pivot_url_to_use and not is_pivot:
                    try:
                        pivot_obj = await self.pivot_mgr.get_pivot()
                        pivot_short = pivot_obj.short() if pivot_obj else "unknown_pivot"
                        logger.info(f"[↔] [AUDIT] {pivot_short} → {p.short()}")
                    except Exception:
                        pass

                start_val_time = time.time()
                async with self.verification_in_flight_sem:
                    proxy_to_use = pivot_url if (self.args.opsec or self.args.proxy_only) and not is_pivot else p.format_url()
                    val_response = await self.v_session.get(
                        test_target, 
                        proxy=p.format_url() if is_pivot else (pivot_url_to_use or p.format_url()),
                        headers={"User-Agent": ua_check}, 
                        timeout=self.config['CONN']['TIMEOUT']
                    )
                latency_val = round(time.time() - start_val_time, 2)
                if val_response.status_code == 200 and val_response.content:
                    data = val_response.json()
                    reported_ip = data.get("query") or data.get("ip") or data.get("origin", "")
                    if reported_ip == p_ip_during_check:
                        p.anonymity = "Elite"
                    else:
                        if self.host_address and reported_ip != self.host_address:
                            p.anonymity = "Anonymous"
                        else:
                            p.anonymity = "Transparent"

                    p.latency = latency_val
                    p.working = True
                    p.verified = True
                    p.time_check = datetime.now(timezone.utc).isoformat()
                    p.country = data.get("countryCode", p.country)
                    p.city = data.get("city", p.city)
                    p.isp = data.get("isp", p.isp)
                    p.org = data.get("org", p.org)
                    p.asn = data.get("as", p.asn)
                    if _stats_reporter and not is_pivot: _stats_reporter.metrics["successful_validations"] += 1
                    # Extra audit via pivot (geo/ASN enrichment)
                    if not self.args.no_audit_via_pivot and pivot_url_to_use:
                        try:
                            current_pivot_url = await self.get_pivot_url(wait_if_missing=False)
                            if current_pivot_url:
                                audit_url = f"http://ip-api.com/json/{p.ip}?fields=status,countryCode,city,isp,org,as"
                                async with self.verification_in_flight_sem:
                                    audit_resp = await self.h_session.get(
                                        audit_url, 
                                        proxy=current_pivot_url, 
                                        timeout=self.config['CONN']['TIMEOUT']
                                    )
                                if _stats_reporter:
                                    _stats_reporter.metrics["network_requests"] += 1
                                if audit_resp.status_code == 200 and audit_resp.content:
                                    audit_data = audit_resp.json()
                                    p.country = audit_data.get("countryCode", p.country)
                                    p.city = audit_data.get("city", p.city)
                                    p.isp = audit_data.get("isp", p.isp)
                                    p.org = audit_data.get("org", p.org)
                                    p.asn = audit_data.get("as", p.asn)
                        except Exception:
                            pass 
                    # DNS Leak Check
                    if not self.args.no_dns_leak_check:
                        try:
                            dns_leak_start = time.time()
                            async with self.verification_in_flight_sem:
                                dns_resp = await self.v_session.get(
                                    "http://edns.ip-api.com/json", 
                                    proxy=p.format_url(), 
                                    timeout=8
                                )
                            if _stats_reporter:
                                _stats_reporter.metrics["network_requests"] += 1
                            if dns_resp.status_code == 200 and dns_resp.content:
                                dns_data = dns_resp.json()
                                dns_geo_block = dns_data.get("dns", {}).get("geo", "").upper() or "UNKNOWN"
                                
                                if dns_geo_block != "UNKNOWN":
                                    if self.host_country_code and p.country != "??":
                                        p.leak_dns = self.host_country_code in dns_geo_block and p.country != self.host_country_code
                                        if p.leak_dns:
                                            logger.warning(f"DNS leak detected for {p.ip}! Host Cn: {self.host_country_code}, Prx Cn: {p.country}")
                                        p.dns_leak_test_latency = round(time.time() - dns_leak_start, 2)
                        except Exception as e_dns:
                            if _stats_reporter:
                                _stats_reporter.metrics["network_errors"] += 1
                    else:
                        p.leak_dns = False
                    
                    if update_db:
                        await self.db.upsert(p)
                    return True
                else:
                    p.working, p.verified, p.time_check = False, False, datetime.now(timezone.utc).isoformat()
                    if update_db:
                        await self.db.upsert(p)
                    if _stats_reporter and not is_pivot:
                        _stats_reporter.metrics["failed_validations"] += 1
                    
            except Exception as e_main:
                if _stats_reporter:
                    _stats_reporter.metrics["network_errors"] += 1
                
            # Final failure path
            p.working = False
            p.verified = False
            p.latency = None
            p.time_check = datetime.now(timezone.utc).isoformat()
            p.anonymity = "Unknown"
            p.country = "??"
            p.city = "Unknown"
            if update_db:
                await self.db.upsert(p)
            if _stats_reporter and not is_pivot:
                _stats_reporter.metrics["failed_validations"] += 1
            return False


    async def run(self):
        logger.info(f"NGF {__version__} STARTING.")
        global _stats_reporter
        _stats_reporter = StatsReporter()
        await self.db.init()
        opsec_mode_activated = self.args.opsec or self.args.proxy_only
        pivot_after_active = getattr(self.args, 'pivot_after', None) is not None
        bg_health_task = None
        # Start pivot health monitor if OpSec OR --pivot-after is used
        if opsec_mode_activated or pivot_after_active:
            if opsec_mode_activated:
                if not await self.establish_pivot_proxy():
                    logger.critical("Failed to establish initial pivot in OpSec mode. Aborting.")
                    await self.db.close()
                    return
            logger.info("[↔] Starting pivot health & rotation monitor...")
            bg_health_task = asyncio.create_task(self.check_pivot_health_and_rotate())
            bg_task_tracker.add(bg_health_task)
            bg_health_task.add_done_callback(bg_task_tracker.discard)
        else:
            await self.resolve_hosts_public_info()
        json_sources_to_load = []
        if getattr(self.args, 'json_remote_url', None):
            json_sources_to_load.append(self.args.json_remote_url)
        if getattr(self.args, 'update_json', None):
            # In args, this would be a path; adjust attribute name as needed
            json_sources_to_load.append(getattr(self.args, 'json_path', None))
        if getattr(self.args, 'validate_json', None):
            json_sources_to_load.append(getattr(self.args, 'json_path', None))

        for json_src in json_sources_to_load:
            if not json_src:
                continue
            try:
                loaded = await self.load_json_proxies(json_src)
                existing_keys = {(c.ip, c.port, c.proto) for c in candidates}
                added = 0
                for lp in loaded:
                    if (lp.ip, lp.port, lp.proto) not in existing_keys:
                        candidates.append(lp)
                        existing_keys.add((lp.ip, lp.port, lp.proto))
                        added += 1
                logger.info(f"Added {added} proxies from JSON source `{json_src}`")
            except Exception as e:
                logger.error(f"Failed to load JSON source `{json_src}`: {e}")
        candidates = await self.find_candidate_proxies(
            types_needed=self.args.type, 
            apply_smart_filters=True
        )
        if not candidates:
            logger.error("No candidates found for validation.")
            await self.db.close()
            return
        logger.info(f"Starting main validation loop on {len(candidates)} candidates...")
        progress = Progress(SpinnerColumn(style="cyan"),TextColumn("[bold blue]{task.description}"),BarColumn(bar_width=40, style="blue", complete_style="green"),TextColumn("[bold white]{task.completed}/{task.total}"),TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),TextColumn("[bold green]Found: {task.fields[found_count]:>4}[/]"),TextColumn("[bold yellow] | Skipped: {task.fields[skipped_count]:>4}[/]"),TimeElapsedColumn(),console=CONSOLE,transient=False,refresh_per_second=10,)
        with progress:
            task_id = progress.add_task("Validating...", total=len(candidates), found_count=0, skipped_count=0)
            async def validation_worker(work_queue: asyncio.Queue):
                while not self.term_event.is_set():
                    try:
                        p_to_check = work_queue.get_nowait()
                    except asyncio.QueueEmpty:
                        try:
                            await asyncio.sleep(0.05)
                        except asyncio.CancelledError:
                            break
                        continue

                    try:
                        pivot_url = await self.pivot_mgr.get_pivot_url()
                        use_pivot = pivot_url is not None
                        try:
                            success = await asyncio.wait_for(
                                self.perform_proxy_test(p_to_check, is_pivot=use_pivot, for_audit=False),
                                timeout=self.config['CONN']['TIMEOUT'] * 2 + 8
                            )
                        finally:
                            await self.pivot_mgr.increment_validation_count()

                        progress.advance(task_id)
                        if success and p_to_check.latency and p_to_check.latency <= self.args.max_latency:
                            cc = p_to_check.country.upper() if p_to_check.country else "??"
                            if (not self.pref_countries or cc in self.pref_countries) and cc not in self.excl_countries:
                                if len(self.working_proxies) < self.args.limit:
                                    self.working_proxies.append(p_to_check)
                                    new_found_ct = len(self.working_proxies)
                                    progress.update(task_id, found_count=new_found_ct)

                                    logger.info(
                                        f"[→][GOOD] {p_to_check.proto.upper():7} {p_to_check.ip:15}:{str(p_to_check.port):<5} "
                                        f"| L: {p_to_check.latency:5.2f}s | A: {p_to_check.anonymity:9} | CC: {cc:3} "
                                        f"| DNS: {'LEAK' if p_to_check.leak_dns else 'OK'}"
                                    )

                                    CONSOLE.print(
                                        f"[bold green]✓[/] {p_to_check.proto.upper():7} "
                                        f"[cyan]{p_to_check.ip:15}[/]:[yellow]{p_to_check.port:<5}[/] "
                                        f"| L: [magenta]{p_to_check.latency:5.2f}s[/] "
                                        f"| A: [bold]{p_to_check.anonymity:9}[/] "
                                        f"| CC: [blue]{cc:3}[/] "
                                        f"| DNS: {'[red]LEAK[/]' if p_to_check.leak_dns else '[green]OK[/]'}"
                                    )

                                    if new_found_ct >= self.args.limit:
                                        logger.info(f"[→] Validation LIMIT ({self.args.limit}) reached.")
                                        self.term_event.set()
                                else:
                                    progress.update(task_id, description="→ Hit Global Limit")
                        else:
                            progress.update(
                                task_id, 
                                description="Validating...", 
                                skipped_count=progress.tasks[task_id].fields.get('skipped_count', 0) + 1
                            )
                    except asyncio.CancelledError:
                        logger.debug(f"← Worker cancelled while testing {p_to_check.short() if hasattr(p_to_check, 'short') else p_to_check}")
                        break
                    except asyncio.TimeoutError:
                        logger.warning(f"Proxy test timeout for {p_to_check.short() if hasattr(p_to_check, 'short') else p_to_check}")
                        p_to_check.working = False
                    except Exception as e_worker:
                        logger.error(f"Worker error on {getattr(p_to_check, 'ip', 'unknown')}: {e_worker}")
                    finally:
                        try:
                            work_queue.task_done()
                        except Exception:
                            pass

            work_queue = asyncio.Queue()
            for p in candidates:
                work_queue.put_nowait(p)

            worker_tasks = []
            for _ in range(min(self.args.threads, len(candidates))):
                t = asyncio.create_task(validation_worker(work_queue))
                worker_tasks.append(t)
             
            try:
                await work_queue.join()
                logger.info("All candidate validations completed.")
            except asyncio.CancelledError:
                logger.info("Validation loop was cancelled.")
            finally:
                for wt in worker_tasks:
                    wt.cancel()
                await asyncio.gather(*worker_tasks, return_exceptions=True)
                progress.stop()
                logger.info(f"Validation complete. Found {len(self.working_proxies)} suitable proxies.")

        self.save_results_to_outputs()
        logger.info(f"Run completed. Found {len(self.working_proxies)} proxies.")

        if self.args.stats and _stats_reporter:
            await _stats_reporter.print_rich_summary(CONSOLE)

        # Cleanup background task
        if bg_health_task:
            bg_health_task.cancel()
            try: await bg_health_task
            except asyncio.CancelledError: pass
            except Exception: pass

        await self.db.close()

    def _export_clash_config(self, proxies: List[proxy], filepath: Path):
        """Export to Clash Meta / Clash for Windows format"""
        config = {
            "mixed-port": 7890,
            "mode": "rule",
            "log-level": "info",
            "proxies": [],
            "proxy-groups": [
                {
                    "name": "NGF-Auto",
                    "type": "select",
                    "proxies": []
                }
            ],
            "rules": [
                "MATCH,NGF-Auto"
            ]
        }

        for p in proxies:
            proxy_entry = {
                "name": f"{p.country}_{p.ip}:{p.port}",
                "type": p.proto if p.proto in ["http", "socks5"] else "socks5",
                "server": p.ip,
                "port": p.port,
            }
            if p.proto == "socks5":
                proxy_entry["udp"] = True
            
            config["proxies"].append(proxy_entry)
            config["proxy-groups"][0]["proxies"].append(proxy_entry["name"])

        filepath.write_text(yaml.dump(config, default_flow_style=False, sort_keys=False))
        logger.info(f"→ Saved Clash config to {filepath}")


    def _export_singbox_config(self, proxies: List[proxy], filepath: Path):
        """Export to sing-box / sing-box compatible format"""
        config = {
            "log": {"level": "info"},
            "inbounds": [
                {"type": "mixed", "listen": "127.0.0.1", "listen-port": 7890}
            ],
            "outbounds": [],
            "route": {
                "rules": [{"outbound": "NGF-Auto"}],
                "auto-detect-interface": True
            }
        }

        for p in proxies:
            outbound = {
                "type": "socks" if p.proto == "socks5" else "http",
                "tag": f"{p.country}_{p.ip}:{p.port}",
                "server": p.ip,
                "server_port": p.port,
            }
            if p.proto == "socks5":
                outbound["version"] = "5"
            
            config["outbounds"].append(outbound)

        filepath.write_text(json.dumps(config, indent=2))
        logger.info(f"→ Saved sing-box config to {filepath}")

    def _export_proxychains(self, proxies: List[proxy], filepath: Path):
        """Dedicated proxychains export with clean formatting"""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        cl = getattr(self.args, 'chain_length', None) or len(proxies)
        
        lines = [
            f"# Generated by NGF v{__version__} | {ts}",
            f"# Total working proxies: {len(self.working_proxies)} | Used in chain: {cl}",
            f"# Command used: {' '.join(sys.argv)}",
            "",
            "strict_chain",
            "tcp_read_time_out 15000",
            "tcp_connect_time_out 8000",
            "remote_dns_subnet 224",
            "proxy_dns",
            "[ProxyList]",
        ]

        # Optional Tor at the top
        if getattr(self.args, 'append_tor', False):
            lines.append("socks5  127.0.0.1   9050")
        lines.append("")
        for p in proxies:
            # Clean alignment
            proto_str = p.proto.ljust(8)
            ip_str = p.ip.ljust(18)
            port_str = str(p.port).ljust(6)
            lines.append(f"{proto_str}{ip_str}{port_str}")
        filepath.write_text("\n".join(lines))
        logger.info(f"→ Saved proxychains config to {filepath}")

    def save_results_to_outputs(self):
        if not self.working_proxies:
            logger.warning("No working proxies to export.")
            return
        export_base_list = list(self.working_proxies)
        if getattr(self.args, 'filter_elite_only', False):
            export_base_list = [p for p in export_base_list if p.anonymity == "Elite"]
        min_lat = getattr(self.args, 'chain_min_latency', None)
        max_lat = getattr(self.args, 'chain_max_latency', None)
        if min_lat is not None or max_lat is not None:
            export_base_list = [
                p for p in export_base_list
                if (min_lat is None or (p.latency and p.latency >= min_lat)) and
                   (max_lat is None or (p.latency and p.latency <= max_lat))
            ]
        if getattr(self.args, 'shuffle_chains', False):
            random.shuffle(export_base_list)
        else:
            export_base_list.sort(key=lambda prx: (
                prx.country.upper() not in self.pref_countries if self.pref_countries else False,
                prx.anonymity != "Elite",
                prx.latency is None,
                prx.latency or 9999
            ))
        final_list = export_base_list[: (getattr(self.args, 'chain_length', None) or len(export_base_list))]
        base_dir = Path(self.args.output_path)
        base_dir.mkdir(parents=True, exist_ok=True)
        # === Proxychains Export ===
        if self.args.proxychains_output:
            pc_path = base_dir / self.args.proxychains_output
            self._export_proxychains(final_list, pc_path)
        # === JSON Metadata ===
        if self.args.json_metadata_output:
            ts_j = datetime.now(timezone.utc).isoformat()
            meta_out = {
                "timestamp": ts_j,
                "version": __version__,
                "author": __author__,
                "source": "validation_run",
                "filters_applied": {
                    "pref_countries": list(self.pref_countries),
                    "excl_countries": list(self.excl_countries),
                    "min_latency": getattr(self.args, 'chain_min_latency', None),
                    "max_latency": getattr(self.args, 'chain_max_latency', None),
                    "limit": self.args.limit
                },
                "count": len(final_list),
                "proxies": [p.format_json() for p in final_list]
            }
            json_path = base_dir / self.args.json_metadata_output
            # Use the --indent-json argument (stored in args from parser)
            indent_level = getattr(self.args, 'indent_json', 2)
            json_path.write_text(json.dumps(meta_out, indent=indent_level))
            logger.info(f"→ Saved JSON metadata to `{json_path}`")
        #> TXT
        if getattr(self.args, 'txt_output', None):
            txt_path = base_dir / self.args.txt_output
            lines = [p.short() for p in final_list]
            txt_path.write_text("\n".join(lines))
            logger.info(f"→ Saved simple TXT list to {txt_path}")
        #> Clash Config
        if getattr(self.args, 'clash_output', None):
            clash_path = base_dir / self.args.clash_output
            self._export_clash_config(final_list, clash_path)
        #> Sing-box Config
        if getattr(self.args, 'singbox_output', None):
            sing_path = base_dir / self.args.singbox_output
            self._export_singbox_config(final_list, sing_path)

        if not any([
            self.args.proxychains_output,
            self.args.json_metadata_output,
            getattr(self.args, 'txt_output', None),
            getattr(self.args, 'clash_output', None),
            getattr(self.args, 'singbox_output', None)
        ]):
            logger.warning("No output format specified. Use --proxychains-output, --clash-output, --txt-output, etc.")

    async def handle_db_operations(self) -> bool:
        """
        Handle all --db-* operations.
        Returns True if a DB-only operation was performed (so main() can exit early).
        """
        # Check if any DB-related flag is active
        if not any([
            self.args.db_dump,
            self.args.db_count,
            self.args.db_clear,
            self.args.db_ip,
            self.args.db_country,
            self.args.db_proto,
            self.args.db_max_latency,
            self.args.db_anonymity,
            self.args.db_via,
            getattr(self.args, 'db_import', None),
            getattr(self.args, 'db_json_export', None),
        ]):
            return False

        logger.info("Database operation mode activated — skipping full scan.")
        await self.db.init()

        performed_operation = False

        #> Clear
        if self.args.db_clear:
            await self.db.clear()
            CONSOLE.print("[bold green]✓ Database successfully cleared.[/]")
            performed_operation = True

        #> Stats
        elif self.args.db_count or self.args.stats:
            stats = await self.db.statistics()
            table = Table(title="NGF Database Statistics")
            table.add_column("Metric", style="dim")
            table.add_column("Value", justify="right", style="bold")
            for k, v in stats.items():
                table.add_row(k, str(v))
            CONSOLE.print(table)
            performed_operation = True

        #> Import
        elif getattr(self.args, 'db_import', None):
            try:
                count = await self.db.import_from_json(self.args.db_import)
                CONSOLE.print(f"[bold green]✓ Imported {count} proxies from `{self.args.db_import}`[/]")
            except Exception as e:
                CONSOLE.print(f"[bold red]✗ Import failed: {e}[/]")
            performed_operation = True

        #> Export Json
        elif getattr(self.args, 'db_json_export', None):
            try:
                filters = {
                    'ip': self.args.db_ip,
                    'country': self.args.db_country,
                    'max_latency': getattr(self.args, 'db_max_latency', None),
                    'proto': self.args.db_proto,
                    'anonymity': self.args.db_anonymity,
                    'via': self.args.db_via,
                    'include_working': True,
                    'include_dead': not getattr(self.args, 'skip_all_dead', False),
                }
                #> Clean filters
                filters = {k: v for k, v in filters.items() if v is not None}

                success = await self.db.export_to_json(self.args.db_json_export, **filters)
                if success:
                    CONSOLE.print(f"[bold green][✓] Database exported to `{self.args.db_json_export}`[/]")
                else:
                    CONSOLE.print("[yellow]No matching entries found or export failed.[/]")
            except Exception as e:
                CONSOLE.print(f"[bold red]✗ JSON export failed: {e}[/]")
                logger.error(f"Export error: {e}")
            performed_operation = True

        # Dump (Table View)
        elif self.args.db_dump:
            filters = {
                'ip': self.args.db_ip,
                'country': self.args.db_country,
                'max_latency': getattr(self.args, 'db_max_latency', None),
                'proto': self.args.db_proto,
                'anonymity': self.args.db_anonymity,
                'via': self.args.db_via,
                'include_working': True,
                'include_dead': not getattr(self.args, 'skip_all_dead', False),
            }
            results = await self.db.qIndex(**{k: v for k, v in filters.items() if v is not None})

            if not results:
                CONSOLE.print("[yellow]No proxies found matching the filters.[/]")
            else:
                table = Table(title=f"NGF Database Dump — {len(results)} proxies")
                table.add_column("Proto")
                table.add_column("IP:Port")
                table.add_column("Status")
                table.add_column("Latency")
                table.add_column("Anonymity")
                table.add_column("Country")
                table.add_column("Via")

                for p in results[:1500]:  # safety cap
                    status = "✓" if p.working else "✗"
                    lat = f"{p.latency:.2f}s" if p.latency else "??"
                    table.add_row(
                        p.proto.upper(),
                        f"{p.ip}:{p.port}",
                        status,
                        lat,
                        p.anonymity,
                        p.country,
                        p.via[:40] + "..." if len(p.via) > 40 else p.via
                    )
                CONSOLE.print(table)
            performed_operation = True

        await self.db.close()
        return performed_operation

#>Init
bg_task_tracker = set()


async def cleanup_bg_tasks_at_exit(signal_received=None):
    logger.info(f"Initiating shutdown cleanup... (Signal: {signal_received})")
    global _stats_reporter
    shutdown_timeout = DEFAULT_CONFIG['CONN'].get('SHUTDOWN_TIMEOUT', 15)
    
    if _stats_reporter and getattr(args_global_ref, 'stats', False):
        try:
            await _stats_reporter.print_rich_summary(CONSOLE)
        except Exception:
            pass
    for task in list(bg_task_tracker):
        if not task.done():
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=shutdown_timeout / 2)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
            except Exception as e:
                logger.debug(f"Background task cleanup error: {e}")

    bg_task_tracker.clear()
    try:
        current_task = asyncio.current_task()
        all_tasks = [t for t in asyncio.all_tasks() if t is not current_task and not t.done()]
        if all_tasks:
            for t in all_tasks:
                t.cancel()
            await asyncio.wait_for(
                asyncio.gather(*all_tasks, return_exceptions=True),
                timeout=shutdown_timeout / 2
            )
    except Exception as e:
        logger.debug(f"Remaining tasks cleanup error: {e}")

    logger.info("Cleanup completed.")

async def run_instructions_from_file(instructions_path: str, config_override_path: Optional[str] = None):
    path_obj = Path(instructions_path)
    if not path_obj.exists():
        logger.critical(f"Instructions file not found: {instructions_path}")
        sys.exit(1)

    logger.info(f"Loading run instructions from: {instructions_path}")
    try:
        with open(path_obj, 'r') as f_ins:
            if instructions_path.endswith(".json"):
                ins_conf = json.load(f_ins)
            else:
                ins_conf = yaml.safe_load(f_ins)
    except Exception as e_ins:
        logger.critical(f"Failed to load instructions: {e_ins.__class__.__name__}: {e_ins}")
        sys.exit(1)

    initial_config_path = getattr(args_global_ref, 'load_config', None) 
    base_config = DEFAULT_CONFIG.copy()
    if initial_config_path:
        try:
            base_config = load_config_file(initial_config_path)
        except Exception as e_conf_load:
            logger.error(f"Overriding base config with defaults due to load error: {e_conf_load}")

    instr_specific_cfg_path = ins_conf.get("config_file_from_instructions")
    if instr_specific_cfg_path:
        try:
            ins_overlay = load_config_file(instr_specific_cfg_path)
            for key, value in ins_overlay.items():
                if isinstance(value, dict) and isinstance(base_config.get(key), dict):
                    base_config[key].update(value)
                else:
                    base_config[key] = value
        except Exception as e_cfg_ins:
            logger.warning(f"Instruction-specific config file could not be loaded: {e_cfg_ins.__class__.__name__}: {e_cfg_ins}")

    effective_args = argparse.Namespace(**{
        "type": ins_conf.get("type", ["socks5"]),
        "limit": ins_conf.get("limit", base_config["CONN"]["MAX_PROXY_LIMIT"]),
        "threads": ins_conf.get("threads", base_config["CONN"]["CONCURRENCY_LIMIT"]),
        "network_concurrency": ins_conf.get("network_concurrency", base_config["CONN"]["NETWORK_CONCURRENCY_LIMIT"]),
        "max_latency": ins_conf.get("max_latency", base_config["CONN"]["MAX_LATENCY"]),
        "timeout": ins_conf.get("timeout", base_config["CONN"]["TIMEOUT"]),
        "pivot_limit_if_set": ins_conf.get("pivot_limit", base_config["CONN"]["PIVOT_USAGE_LIMIT"]),
        "db_fname": ins_conf.get("db_filename", base_config["CONN"]["DBPATH"]),
        "db_path": ins_conf.get("db_path", "."), 
        "opsec": ins_conf.get("opsec", False),
        "proxy_only": ins_conf.get("proxy_only", False),
        "fetch_new_sources": True,
        "skip_all_dead": ins_conf.get("skip_all_dead", False),
        "proxychains_output": ins_conf.get("proxychains_output", "from_instr.conf"),
        "json_metadata_output": ins_conf.get("json_metadata_output", None),
        "max_sources_per_type": ins_conf.get("max_sources_per_type", 999),
        "output_path": ins_conf.get("output_path", "ngf_outputs"),
        "shuffle_chains": ins_conf.get("shuffle_chains", False),
        "no_dns_leak_check": ins_conf.get("no_dns_leak_check", False),
        "disable_progress_bars": ins_conf.get("disable_progress_bars", False),
        "country_filter": ",".join(ins_conf.get("country_filter", [])),
        "exclude_country": ",".join(ins_conf.get("exclude_country", [])),
        "stats": ins_conf.get("collect_stats", False), 
        "skip_recently_validated": ins_conf.get("skip_recent", False),
        "skip_recency_hours": ins_conf.get("skip_recency_hours", 1),
        "pivot_after": ins_conf.get("pivot_after", None),
        "pivot_limit": ins_conf.get("pivot_limit", 30),
        "filter_elite_only": ins_conf.get("filter_elite_only", False),
        "chain_min_latency": ins_conf.get("chain_min_latency", None),
        "chain_max_latency": ins_conf.get("chain_max_latency", None),
        "chain_length": ins_conf.get("chain_length", None),
        "append_tor": ins_conf.get("append_tor", False),
        "verbose": ins_conf.get("verbose", False),
        "show_config": ins_conf.get("show_config", False),
    }) 
    
    try:
        fetcher_instance = NGFetcher(effective_args, base_config)
        await fetcher_instance.run()
    except Exception as e_run:
        logger.error(f"Workflow execution based on instructions failed: {e_run.__class__.__name__}: {e_run}")
        sys.exit(1)
    
args_global_ref: argparse.Namespace = argparse.Namespace()

async def main():
    global args_global_ref, _stats_reporter
    parser = argparse.ArgumentParser(
        description=f"NGF v{__version__} - Advanced Proxy Fetcher, Validator & Chain Builder",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    io_group = parser.add_argument_group("Input/Output & Operation Modes")
    io_group.add_argument("--load-config", 
                          help="Path to a configuration file (JSON or YAML) to load initial settings.")
    io_group.add_argument("--load-instructions", 
                          help="Path to an instructions file (JSON/YAML) that defines a complete run. "
                               "Runs the tool non-interactively based on the file.")
    io_group.add_argument("--instruction-template", 
                          action="store_true",
                          help="Print a sample instructions/template file and exit.")

    run_group = parser.add_argument_group("Run Controls")
    run_group.add_argument("--threads", "-t", type=int, 
                           default=DEFAULT_CONFIG['CONN']['CONCURRENCY_LIMIT'],
                           help="Number of concurrent proxy validation workers.")
    run_group.add_argument("--network-concurrency", type=int, 
                           default=DEFAULT_CONFIG['CONN']['NETWORK_CONCURRENCY_LIMIT'],
                           help="Maximum number of simultaneous network requests (source fetching).")
    run_group.add_argument("--type", choices=["http", "https", "socks4", "socks5"], nargs="+", 
                           default=["socks5"],
                           help="Proxy protocol(s) to fetch and validate.")
    run_group.add_argument("--limit", "-l", type=int, 
                           default=DEFAULT_CONFIG['CONN']['MAX_PROXY_LIMIT'],
                           help="Maximum number of working proxies to return.")

    val_group = parser.add_argument_group("Validation Settings")
    val_group.add_argument("--max-latency", type=float, 
                           default=DEFAULT_CONFIG['CONN']['MAX_LATENCY'],
                           help="Maximum acceptable latency in seconds for a proxy to be considered good.")
    val_group.add_argument("--timeout", type=float, 
                           default=DEFAULT_CONFIG['CONN']['TIMEOUT'],
                           help="Request timeout in seconds for proxy validation.")
    val_group.add_argument("--country-filter", 
                           help="Comma-separated list of country codes to prefer (e.g., US,DE,GB).")
    val_group.add_argument("--exclude-country", 
                           help="Comma-separated list of country codes to exclude (e.g., CN,RU).")

    out_group = parser.add_argument_group("Output Options")
    out_group.add_argument("--output-path", default="ngf_outputs",
                           help="Base directory where output files will be saved.")
    out_group.add_argument("--txt-output", 
                           help="Filename for simple one-proxy-per-line TXT output")
    out_group.add_argument("--clash-output", 
                           help="Filename for Clash Meta config (e.g. clash.yaml)")
    out_group.add_argument("--singbox-output", 
                           help="Filename for sing-box config (e.g. singbox.json)")
    out_group.add_argument("--proxychains-output", 
                           help="Filename for proxychains configuration file (e.g., 'my_chain.conf').")
    out_group.add_argument("--json-metadata-output", 
                           help="Filename for detailed JSON metadata export (e.g., 'results.json').")
    out_group.add_argument("--indent-json", type=int, default=2,
                           help="Indentation level for JSON output files.")
    out_group.add_argument("--stats", action="store_true",
                           help="Print detailed execution statistics at the end of the run.")

    opt_group = parser.add_argument_group("Options & Features")
    opt_group.add_argument("--fetch-new-sources", action="store_true",
                           help="Always fetch fresh proxies from remote sources (even if DB has entries).")
    opt_group.add_argument("--skip-all-dead", action="store_true",
                           help="Skip proxies previously marked as dead in the database.")
    opt_group.add_argument("--skip-recently-validated", action="store_true",
                           help="Skip proxies that were recently validated successfully.")
    opt_group.add_argument("--skip-recency-hours", type=float, default=1.0,
                           help="Consider proxies validated within this many hours as 'recent'.")
    opt_group.add_argument("--update-json", action="store_true",
                           help="Update local JSON cache from sources (legacy mode).")
    opt_group.add_argument("--validate-json", action="store_true",
                           help="Validate proxies loaded from a local JSON cache.")
    io_group.add_argument("--json-remote-url", 
                           help="URL to a remote JSON file (supports .json, .gz, .tar.gz)")
    opt_group.add_argument("--json-remote-load", action="store_true",
                           help="Load proxy list from a remote JSON URL.")
    opt_group.add_argument("--opsec", action="store_true",
                           help="Enable OpSec mode: route all traffic through a pivot proxy.")
    opt_group.add_argument("--proxy-only", action="store_true",
                           help="Only use proxies (no direct connections), implies OpSec mode.")
    opt_group.add_argument("--no-dns-leak-check", action="store_true",
                           help="Disable DNS leak detection during validation.")
    opt_group.add_argument("--no-audit-via-pivot", action="store_true",
                           help="Disable additional geo/ASN audit through pivot proxy.")
    opt_group.add_argument("--shuffle-chains", action="store_true",
                           help="Randomize the order of proxies in output files.")
    opt_group.add_argument("--filter-elite-only", action="store_true",
                           help="Only export Elite (highest anonymity) proxies.")
    opt_group.add_argument("--chain-min-latency", type=float,
                           help="Minimum latency (seconds) for proxies in output chain.")
    opt_group.add_argument("--chain-max-latency", type=float,
                           help="Maximum latency (seconds) for proxies in output chain.")
    opt_group.add_argument("--chain-length", type=int,
                           help="Limit the number of proxies in the final output chain.")
    opt_group.add_argument("--disable-progress-bars", action="store_true",
                           help="Disable rich progress bars during validation.")
    opt_group.add_argument("--append-tor", action="store_true",
                           help="Append Tor (127.0.0.1:9050) at the top of proxychains config.")

    db_group = parser.add_argument_group("Database Management")
    db_group.add_argument("--db-fname", default=DEFAULT_CONFIG["CONN"]["DBPATH"],
                          help="Database filename.")
    db_group.add_argument("--db-path", default=".",
                          help="Directory where the SQLite database is stored.")
    db_group.add_argument("--db-fetch-max-age", type=float,
                          help="Ignore database entries older than this many hours when selecting candidates.")
        # Inside the parser setup, under db_group
    db_group.add_argument("--db-dump", action="store_true", 
                          help="Dump filtered proxies from DB.")
    db_group.add_argument("--db-count", action="store_true", 
                          help="Show database statistics.")
    db_group.add_argument("--db-clear", action="store_true", 
                          help="Clear ALL data from database.")
    db_group.add_argument("--db-ip", 
                          help="Filter by IP.")
    db_group.add_argument("--db-country", 
                          help="Filter by country code.")
    db_group.add_argument("--db-proto", 
                          help="Filter by protocol (http/https/socks4/socks5).")
    db_group.add_argument("--db-max-latency", type=float, 
                          help="Max latency filter.")
    db_group.add_argument("--db-anonymity", 
                          help="Filter by anonymity (Elite/Anonymous/Transparent).")
    db_group.add_argument("--db-via", 
                          help="Filter by source (via).")
    db_group.add_argument("--db-import", 
                          help="Import proxy metadata from a JSON file into the database (format: list or {index: [...]})")
    db_group.add_argument("--db-json", "--db-json-export",
                          dest="db_json_export",
                          metavar="FILE",
                          help="Export filtered DB contents to JSON and exit (e.g. --db-json proxies.json)")
    

    sources_group = parser.add_argument_group("Source & Tuning")
    sources_group.add_argument("--load-source-counts", action="store_true",
                               help="Log detailed source URL statistics (debugging).")
    sources_group.add_argument("--max-sources-per-type", type=int, default=999,
                               help="Maximum number of source URLs to use per protocol.")

    pivot_group = parser.add_argument_group("Pivot Proxy Control")
    pivot_group.add_argument("--pivot", 
                             help="Manually specify one or more pivot proxies in format proto://ip:port "
                                  "(comma separated).")
    pivot_group.add_argument("--pivot-http-only", action="store_true",
                             help="Only use HTTP/HTTPS proxies as pivots.")
    pivot_group.add_argument("--pivot-after", type=int,
                             help="After validating this many proxies, force use of a pivot proxy.")
    pivot_group.add_argument("--pivot-limit-if-set", type=int, 
                             default=DEFAULT_CONFIG['CONN']['PIVOT_USAGE_LIMIT'],
                             help="Maximum times a pivot proxy can be used before rotation.")


    # Additional flags under Options
    opt_group.add_argument("--verbose", "-v", action="store_true",
                           help="Enable verbose (DEBUG) logging.")
    opt_group.add_argument("--show-config", action="store_true",
                           help="Show effective configuration and exit.")

    # Note: --instruction-template is handled specially before parsing


    if "--instruction-template" in sys.argv:
        template = {
            "## NGF Instructions File Template ##": None,
            "type": ["socks5", "http"],
            "limit": 500,
            "threads": 20,
            "network_concurrency": 150,
            "max_latency": 5.0,
            "timeout": 12.0,
            "pivot_limit": 25,
            "db_filename": "custom_ngf_state.db",
            "db_path": ".",
            "db_fetch_max_age": 24.0,
            "opsec": False,
            "proxy_only": False,
            "skip_all_dead": True,
            "skip_recent": True,
            "skip_recency_hours": 2.0,
            "fetch_new_sources": True,
            "max_sources_per_type": 5,
            "proxychains_output": "my_proxy_list.conf",
            "json_metadata_output": "results_full.json",
            "collect_stats": True,
            "output_path": "results",
            "shuffle_chains": False,
            "no_dns_leak_check": False,
            "no_audit_via_pivot": True,
            "filter_elite_only": False,
            "chain_min_latency": 0.5,
            "chain_max_latency": 8.0,
            "chain_length": 10,
            "country_filter": ["US", "DE"],
            "exclude_country": ["CN", "RU"],
            "config_file_from_instructions": "optional_local_config.yaml",
        }
        print(yaml.dump(template, default_flow_style=False, indent=2))
        return

    args = parser.parse_args()
    args_global_ref = args

    config = DEFAULT_CONFIG.copy()
    if args.load_config:
        logger.info(f"Loading configuration from file: {args.load_config}")
        try:
            file_conf = load_config_file(args.load_config)
            for key, value in file_conf.items():
                if isinstance(value, dict) and isinstance(config.get(key), dict):
                    config[key].update(value)
                else:
                    config[key] = value
            logger.info(f"Loaded config from {args.load_config}.")
        except Exception as e:
            logger.critical(f"Failed to load configuration from {args.load_config}: {e.__class__.__name__}: {e}")
            sys.exit(1)

    config = apply_config(config, args)

    if args.load_instructions:
        await run_instructions_from_file(args.load_instructions, config.get("config_file_from_instructions"))
        return

    if args.verbose: logger.setLevel(logging.DEBUG)
    else: logger.setLevel(logging.INFO)

    if args.show_config:
        print()
        table = Table(title="Effective Configuration", show_header=True, header_style="bold magenta")
        table.add_column("Setting", style="dim"); table.add_column("Value")
        table.add_row("Threads", str(config['CONN']['CONCURRENCY_LIMIT']))
        table.add_row("Network Concurrency", str(config['CONN']['NETWORK_CONCURRENCY_LIMIT']))
        table.add_row("Protocols", ", ".join(args.type))
        table.add_row("Limit", str(args.limit))
        table.add_row("OpSec Mode", str(args.opsec))
        CONSOLE.print(table)
        print()
        return

    logger.warning("Free/unauthenticated proxies from public repositories are inherently risky. Use at your discretion.")
    try:
        fetcher_instance = NGFetcher(args, config)
        if await fetcher_instance.handle_db_operations():
            logger.info("DB operation completed. Exiting.")
            return
        loop = asyncio.get_running_loop()
        
        def signal_handler(sig):
            logger.info(f"Received signal {sig}. Shutting down...")
            if hasattr(fetcher_instance, 'term_event') and not fetcher_instance.term_event.is_set():
                fetcher_instance.term_event.set()
            asyncio.create_task(cleanup_bg_tasks_at_exit(sig))

        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda s=sig: signal_handler(s))
        
        await fetcher_instance.run()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received.")
        if 'fetcher_instance' in locals() and hasattr(fetcher_instance, 'term_event'):
            fetcher_instance.term_event.set()
        await cleanup_bg_tasks_at_exit("SIGINT")
    except Exception as e:
        logger.critical(f"Unhandled error in main loop: {e.__class__.__name__}: {e}")
        await cleanup_bg_tasks_at_exit("UNHANDLED_ERROR")
    finally:
        # Final safety cleanup
        if 'fetcher_instance' in locals():
            if hasattr(fetcher_instance, 'db') and fetcher_instance.db:
                try:
                    await fetcher_instance.db.close()
                except Exception:
                    pass

if __name__ == "__main__": asyncio.run(main())
