<h1 align="center">Next-Generation-Fetch</h1>

<p align="center">
  <strong>An enterprise-grade, OpSec-aware proxy harvesting and validation suite</strong><br>
  designed for security professionals and researchers.
</p>

<div align="center">
  <img src="docs/icon.png" height="400" style="margin: 0 10px; border-radius: 8px;">
  <img src="docs/5minScan.png" height="400" style="margin: 0 10px; border-radius: 8px;">
</div>
<p align="center">
  Unlike traditional fetchers, NGF focuses on <strong>stealth pivoting</strong>, <strong>TLS impersonation</strong>, and 
  <strong>persistent state</strong> to provide a high-quality, reliable list of proxies suitable for tools like 
  <code>proxychains</code>.
</p>

---

<p align="center">
Author : J4ck3LSyN | Version: 0.1.3 | License: MIT | Authority: Chaos Foundry Security Division
</p>

---

## Index

- [Key Technical Features](#key-technical-features)
- [Installing Proxychains (recommended)](#installing-proxychains-recommended)
- [Installing NGF](#installing-ngf)
- [All the Details](#all-the-details)
  - [Threads, Types, Limits and Verbosity](#threads-types-limits-and-verbosity)
  - [Proxychains Configuration](#proxychains-configuration)
  - [JSON Files](#json-files)
  - [Sources](#sources)
  - [OpSec and Pivot](#opsec-and-pivot)
- [Working with the Database](#working-with-the-database)
- [Proper Workflow](#proper-workflow)
- [Advanced Technical Notes (v0.1.3)](#advanced-technical-notes-v013)
- [Operational Security (OpSec) Logic](#operational-security-opsec-logic)
- [Disclaimer](#disclaimer)

## Key Technical Features

*   **Persistent SQLite State (WAL Mode):** Uses a local database (`ngf_state.db`) with Write-Ahead Logging for high-concurrency performance. It includes specific PRAGMA optimizations for stability on shared filesystems (like WSL/NFS) and index-driven queries for rapid metadata filtering.
*   **Stealth Pivot Mechanism:** Implements a multi-stage "Phase 0" bootstrap. It prioritizes manual pivots, then high-reliability database seeds, and finally a fresh bootstrap subset to ensure a secure gateway is established before the host IP touches any third-party APIs.
*   **Advanced TLS Impersonation:** Utilizes `curl_cffi` to impersonate a **Chrome 110** browser fingerprint. This bypasses modern anti-bot and CDN-level protections (Cloudflare, Akamai, etc.) that typically block standard Python `requests` or `httpx` headers.
*   **Asynchronous Pipeline:** Leverages Python 3.11+ `TaskGroups` and semaphores for high-concurrency validation without exhausting system resources.
*   **Deep Metadata Validation:**
    *   **Anonymity Detection:** Elite, Anonymous, and Transparent levels.
    *   **Remote DNS (SOCKS5h):** Automatically utilizes `socks5h` for SOCKS5 proxies to ensure DNS resolution happens at the proxy level, preventing local DNS leaks.
    *   **DNS Leak Protection:** Detects if a proxy's DNS resolver matches the host country, signaling a potential identity leak.
    *   **Geo-IP Enrichment:** ISP, ASN, City, and Country code attribution.

---

## Installing Proxychains (recommended)

```bash
# Debian
sudo apt-get install proxychains-ng
# Arch
sudo apt-get install proxychains-ng
# Windows
winget install proxychains-ng # Or proxychains4?
```

## Installing NGF

> NGF requires Python 3.11+ due to the use of `asyncio.TaskGroup`.

1. **Git the Repo**
    ```bash
    git clone https://github.com/J4ck3LSyN-Gen2/NGF.git
    cd NGF
    ```

2. **Setup the Environment**
    ```bash
    python3 -m venv ngf_environ
    source ngf_environ/bin/activate # (.fish) IF you're swimming.
    python3 -m pip install --upgrade pip # Upgrade pip just in case.
    ```

3. **Install the Requirements**
    ```bash
    python3 -m pip install -r requirements.txt
    # Or directly 
    python3 -m pip install rich aiosqlite curl-cffi
    ```

4. **Deactive After**
    ```bash
    deactivate
    ```

---

## All the Details

<p align="center">
    <img src="docs/usage.png" width="750">
</p>

### Threads, Types, Limits and Verbosity
* **Threading**
    This configured the number of concurrent validation workers, note that when using `--opsec` the `pivot` will still work on each indivitual threads. 
    > On initial discoveries without `--opsec` it is recommended to use `<8` threads, the metadata services can & will rate-limit you.
    - _Usage: `python3 ngf013.py --threads <int> ...`_

* **Limits**
    Limit the validation after finding `x` amount.
    - _Usage: `python3 ngf013.py --limit <int> ...`_

* **Types**
    List of proxy protocols to harvest and validation.
    > _Note:_ The default is `socks5`
    - _Usage: `python3 ngf013.py --type <http,https,socks4,socks5> ...`_

* **Verbosity**
    Configured debugging.
    > This nutralizes the `progress bar`, however the amount of information is needed when testing.
    - _Usage: `python3 ngf013.py --verbose ...`_

* **Output**
    Control the `proxychains.conf` output.
    > This is intended to be used inside of `docker` containers where `proxychains` is needed (CAID.php), dropping to `/tmp` specifically.
    - _`python3 ngf013.py --o </my/file/path/proxychains.conf> ...`_
    
* **Examples**
    - `python3 ngf013.py --verbose --limit 100 --threads 10 --type http`
    - `python3 ngf013.py --limit 20 --threads 3 --type socks4,socks5`

### Proxychains Configuration
* **The Different Chain Typess**
    After validation processes, this is used to set the chain type inside of the `proxychains.conf`.
    - _Usage: `python3 ngf013.py ... --chain-type <0,1,2> ...`_
    - __1__ : Dynamic
    - __2__ : Random
    - __3__ : Strict

* **Chain Lengths**
    This tells `proxychains` how many `proxies` we wish to `chain` together, IE: if `2` than it will look something like: `<host> -> <proxy1> -> <proxy2> -> ...`.
    - _Usage: `python3 ngf013.py ... --chain-length <int> ...`_
    - _Note:_ It is wise to not use long chains unless you have already established more than the same amoount in verified proxies.

* **Chain Latency**
    Only use proxies with a specified latency.
    - _`python3 ngf013.py ... --chain-min-latency <float> ...`_

* **Chain Randomization**
    Randomizes the output order in `proxychains.conf`
    - _`python3 ngf013.py ... --chain-shuffle ...`_

* **Minimum Latency**
    Configure a minimum latency.
    - _`python3 ngf013.py ... --min-latency <float> ...`_

### JSON Files
We save `metadata` reports inside of `JSON` for easy sharing and access, this is conceptual and planned to be used as a simpler method of proxy indexing without the sourcing of tens of thousands indivitually.

* **--json**
    Set path for the report
    - _`python3 ngf013.py ... --json <path> ...`_

* **--update-json**
    Re-validates proxies from an existing file and update the metadata.
    - _`python3 ngf013.py ... --update-json <path> ...`_

* **--validate-json**
    Validates procies from a JSON file without new discovery.
    - _`python3 ngf013.py ... --validate-json <path> ...`_


### Sources
Most sources are internal, however they can be sourced via JSON or `--source`

* **Update Sources**
    Force a refresh of canidates from external URLs.
    - _`python3 ngf013.py --update-sources ...`_

* **Unique Source**
    Use a custom source, seperated via `,`.
    - _`python3 ngf013.py --source <url,url> ...`_

* **Skipping the Dead**
    Skip ALL proxies that are found dead in the database.
    - _`python3 ngf013.py --skip-dead ...`_

### OpSec and Pivot
This is where the tool shines, we will `route` discovery and `metadata audits` through a `pivot proxy`. This prevents massive amounts of `quries` to third-party sources from the `host` itself.

* **Unique Pivot**
    Specify a unqiue pivot, IE: Tor.
    - _`python3 ngf013.py ... --pivot http://127.0.0.1:9050 ...`_

* **HTTP Pivoting**
    Forces the pivot the search and prioritiize `HTTP/HTTPS` proxies, this assists in making sure the `third parties` do not flag us instantly.
    - _`python3 ngf013.py ... --pivot-http ...`_

* **Limiting the Pivot**
    Number of uses allowed per-pivot before rotating.
    > _Note:_ It is recommended to gain a decent 50+ validated list prior to implementing this at scale.
    - _`python3 ngf013.py ... --pivot-limit <int> ...`_

* **OpSec**
    This enables `stealth-mode` where we will route `discovery` and `metadata audits` through a `pivot-proxy`, shown above.
    - _`python3 ngf013.py ... ... --opsec`_

* **Proxy Only**
    This forces ALL traffic (including discovery) through a picot, masking the host IP entirely.
    - _`python3 ngf013.py ... ... --proxy-only`_

### Working with the Database
NGF utilizes a persistent SQLite engine to maintain a "Long-Term Memory" of the proxy landscape. Unlike volatile fetchers that lose data on exit, NGF tracks every proxy's historical performance, protocol details, and geographic metadata.

* **Persistent Reliability:**  
    Proxies identified as "Working" are prioritized in subsequent runs as bootstrap seeds, allowing for sub-second start times.
* **Async Concurrency:**  
    Built on `aiosqlite`, the database operations never block the network validation pipeline.
* **Performance Optimized:**  
    Implements `PRAGMA journal_mode=WAL` (Write-Ahead Logging) and `MEMORY` temp stores to ensure high-speed concurrent writes during aggressive discovery phases.
* **Index-Driven Queries:**  
    Every metadata field (Latency, Anonymity, Country, Proto) is indexed, enabling near-instant filtering of tens of thousands of records.

* **Dumping the Database**
    Dumps information from the database.
    - _`python3 ngf013.py --db-dump`_

* **Getting the Numbers**
    Show the statistics.
    - _`python3 ngf013.py --db-count`_

* **Filtering**
    - _`python3 ngf013.py --db-ip <ip>`_
    - _`python3 ngf013.py --db-country <country>`_
    - _`python3 ngf013.py --db-proto <http,https,socks4,socks5>`_
    - _`python3 ngf013.py --db-max-latency <float>`_
    - _`python3 ngf013.py --db-anonymity <elite,anonymous,transparent>`_
    - _`python3 ngf013.py --db-source <url,url>`_

    These can also be combined:
    *   **By IP:** `python3 ngf013.py --db-dump --db-ip 1.2.3.4`
    *   **By Geography:** `python3 ngf013.py --db-dump --db-country US`
    *   **By Protocol:** `python3 ngf013.py --db-dump --db-proto socks5`
    *   **By Latency:** `python3 ngf013.py --db-dump --db-max-latency 1.5`
    *   **By Anonymity:** `python3 ngf013.py --db-dump --db-anonymity Elite`
    *   **By Source:** `python3 ngf013.py --db-dump --db-source github`
    
* **Importing & Exporting**
    These operations are extensions to `json` handling.
    - _`python3 ngf013.py --db-import <path>`:Import a `index.json`_
    - _`python3 ngf013.py --db-json <path>`:Export a `index.json`_

* **Clearing**
    Wipe ALL data from the database.
    - _`python3 ngf013.py --db-clear`_

## Proper Workflow

1. **Warn up the database:** `python3 ngf013.py --limit 28 --threads 4 --type http --update-sources --chain-type 0 --chain-length 2`
2. **Initialize the pivot:** `python3 ngf013.py --limit 256 --threads 16 --type http,socks4,socks5 --json current.json --pivot-http --opsec`


## Advanced Technical Notes (v0.1.3)

> _Note:_ The `database` is used for storing proxies that are `dead` or `pending-validation` along side the `working` ones, you can filter these using `--db-max-latency 7.0` usually resolving only working proxies. Reasoning: most `dead` proxies are never are able to connect resulting in a `null`, the ones that did `connect` but `failed` validation after will usually be `>8.0`.  

<p align="center">
    <img src="docs/dumpExample.png" width="550">
</p>


### Database Optimizations
NGF doesn't just store data; it optimizes for speed. In `ngf013.py`, the `ProxyDB` class implements:
*   **PRAGMA busy_timeout = 5000**: Handles database locks gracefully during high-concurrency writes.
*   **PRAGMA synchronous = NORMAL**: Balances safety and speed.
*   **Batch Upserting**: Discovered candidates are inserted in bulk to minimize disk I/O overhead.

### Error Handling & Resilience
The validator in `ngf013.py` is built to handle the "dirty" nature of public proxies:
*   **Curl Error Mapping**: Specifically identifies and logs timeouts (28), empty replies (52), SSL certificate issues (60), and SOCKS resets (97).
*   **Graceful Shutdown**: Uses signal handlers and `asyncio.Event` to ensure the database is closed and current results are saved even if `Ctrl+C` is pressed.
*   **Pivot Rotation**: If a pivot proxy reaches a user-defined usage limit or fails a background health check, NGF automatically rotates to a new one from the validated pool.

### Pro-Tip: Seeding the Database
For maximum OpSec, run a non-stealth discovery once to "warm" your database:  
- `python3 ngf013.py --limit 100 --threads 4 --type http --update-sources # Clear`
- `python3 mgf013.py --limit 100 --threads 4 --type http --proxy-only http://127.0.0.1:9050 # Route through tor`

Once the database has working proxies, future runs using `--opsec` or `--proxy-only` will be significantly faster as they can pull pivots directly from known-working seeds.

## Operational Security (OpSec) Logic
NGF's OpSec architecture is divided into three distinct phases:

1.  **Phase 0 (Bootstrap):** The tool looks for a "Pivot." It checks manual entries, then DB seeds, and finally a small bootstrap subset of sources. Once a working proxy is found, it is locked as the `Pivot`.
2.  **Phase 1 (Proxied Discovery):** Source URLs are fetched using the Pivot's TLS fingerprint. This prevents third-party list providers from logging your host IP.
3.  **Phase 2 (Proxied Audit):** Candidate proxies are first "audited" via the Pivot using the `ip-api.com` endpoint. This verifies the metadata (Country, ISP, ASN) before your host ever attempts a direct connection to the candidate proxy.


```text
       .----------------.
       |   YOUR HOST    |
       '-------.--------'
               |
               | (Encrypted TLS)
               v
       .----------------.
       |  PIVOT PROXY   | <--- Phase 0: Secure Gateway
       '-------.--------'
               |
      _________|_____________________________
     |         |              |              |
     v         v              v              v
 [Sources] [Metadata] [Geo-IP API] [Candidate Audit]
     '---------+-------.------+--------------'
                       |
                       v
               .----------------.
               | VALIDATED POOL |
               '----------------'
```

<div align="center">
  <img src="docs/dumpExample.png" height="400" style="margin: 0 10px; border-radius: 8px;">
  <img src="docs/pivotExample.png" height="400" style="margin: 0 10px; border-radius: 8px;">
</div>

---

## Disclaimer

Using free public proxies involves inherent risks. These servers are often monitored by the parties providing them. **NGF** is intended for educational and authorized security testing purposes only. Always route sensitive traffic through trusted, encrypted tunnels (VPN/Tor/SSH) in addition to proxy chains.
