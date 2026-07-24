#!/usr/bin/env python3
"""
Bug Bounty Scope Extractor v4.1-FINAL
=====================================
Platform-aware parallel scraper.

SKIPPED (use APIs): HackerOne, YesWeHack, HackenProof, Bugcrowd, Intigriti, BugBounty.ch
JS-SPA platforms need Selenium: Inspectiv, Bugrap, IssueHunt

Working platforms: Immunefi, r.xyz, GoBugFree, Standoff365, BiZone, Cantina, Compass, BugBase, Sherlock
"""

import re
import csv
import json
import time
import logging
import argparse
import urllib.parse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

import requests
from bs4 import BeautifulSoup

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.support.ui import WebDriverWait
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

# ============================================================================
# CONFIG
# ============================================================================

@dataclass
class Config:
    max_workers: int = 6
    request_timeout: int = 25
    selenium_timeout: int = 30
    retry_attempts: int = 3
    retry_delay: float = 2.0
    request_delay: float = 1.0
    use_selenium: bool = True
    headless: bool = True
    output_dir: str = "bug_bounty_results"
    verbose: bool = False
    screenshots: bool = False

CONFIG = Config()

# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class Asset:
    target: str
    asset_type: str = "other"
    instruction: str = ""
    in_scope: bool = True
    def to_dict(self): return asdict(self)

@dataclass
class ProgramScope:
    program_name: str = ""
    platform: str = "unknown"
    url: str = ""
    status: str = "pending"
    assets: List[Asset] = field(default_factory=list)
    extraction_method: str = ""
    error_message: str = ""
    http_status: int = 0
    def to_dict(self):
        return {"program_name": self.program_name, "platform": self.platform, "url": self.url,
                "status": self.status, "assets": [a.to_dict() for a in self.assets],
                "extraction_method": self.extraction_method, "error_message": self.error_message,
                "http_status": self.http_status}

# ============================================================================
# PLATFORM DETECTION
# ============================================================================

PLATFORMS = {
    'immunefi': ['immunefi.com'],
    'rxyz': ['r.xyz'],
    'gobugfree': ['gobugfree.com'],
    'standoff365': ['bugbounty.standoff365.com'],
    'bizon': ['bugbounty.bi.zone'],
    'cantina': ['cantina.xyz'],
    'compass': ['bugbounty.compass-security.com'],
    'bugbase': ['bugbase.ai'],
    'sherlock': ['audits.sherlock.xyz'],
    'issuehunt': ['issuehunt.io'],
    'bugrap': ['bugrap.io'],
    'inspectiv': ['inspectiv.com'],
}

def detect_platform(url: str) -> str:
    url_l = url.lower()
    for platform, domains in PLATFORMS.items():
        for d in domains:
            if d in url_l:
                return platform
    return 'unknown'

# ============================================================================
# SELENIUM
# ============================================================================

class SeleniumManager:
    _instance = None
    _lock = Lock()
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._driver = None
        return cls._instance

    def get_driver(self):
        if not SELENIUM_AVAILABLE:
            return None
        if self._driver is None:
            options = ChromeOptions()
            if CONFIG.headless:
                options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--window-size=1920,1080')
            try:
                self._driver = webdriver.Chrome(options=options)
            except Exception as e:
                logging.error(f"Chrome driver failed: {e}")
                return None
        return self._driver

    def fetch(self, url: str) -> Tuple[str, int]:
        driver = self.get_driver()
        if not driver:
            return "", 0
        try:
            driver.get(url)
            WebDriverWait(driver, CONFIG.selenium_timeout).until(
                lambda d: d.execute_script('return document.readyState') == 'complete')
            time.sleep(4)
            if CONFIG.screenshots:
                d = Path(CONFIG.output_dir) / 'screenshots'
                d.mkdir(exist_ok=True)
                safe = re.sub(r'[^a-zA-Z0-9]', '_', url.split('/')[-1] or 'page')[:50]
                driver.save_screenshot(str(d / f"{safe}.png"))
            return driver.page_source, 200
        except Exception as e:
            logging.warning(f"Selenium failed for {url}: {e}")
            return "", 0

    def close(self):
        if self._driver:
            self._driver.quit()
            self._driver = None

# ============================================================================
# FALSE POSITIVE FILTER
# ============================================================================

FP_DOMAINS = {'localhost', 'example.com', 'test.com', 'github.com', 'etherscan.io',
    'google.com', 'facebook.com', 'twitter.com', 'linkedin.com', 'youtube.com',
    'cloudflare.com', 'jsdelivr.net', 'bootstrapcdn.com', 'googleapis.com',
    'gstatic.com', 'google-analytics.com', 'googletagmanager.com',
    'yandex.ru', 'yandex.com', 'yandexcloud.net', 'yastatic.net',
    'roistat.com', 'mc.yandex.ru', 'cdn.jsdelivr.net'}

FP_EXTS = {'.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.pdf', '.zip'}

def is_fp(target: str) -> bool:
    t = target.lower()
    if any(t.endswith(ext) for ext in FP_EXTS):
        return True
    parsed = urllib.parse.urlparse(t) if t.startswith('http') else urllib.parse.urlparse('//' + t)
    netloc = parsed.netloc.lstrip('*').lstrip('.')
    if len(netloc) < 6:
        return True
    for fp in FP_DOMAINS:
        if fp in netloc or netloc.endswith('.' + fp):
            return True
    return False

# ============================================================================
# EXTRACTION HELPERS
# ============================================================================

def extract_targets(text: str) -> List[Asset]:
    """Extract URLs, contracts, domains from text."""
    assets, seen = [], set()

    # URLs
    for m in re.finditer(r'https?://[^\s<>"\'\)\]\,]+', text):
        url = m.group().rstrip('.,;:')[:500]
        if url not in seen and len(url) > 10 and not is_fp(url):
            seen.add(url)
            assets.append(Asset(target=url, asset_type='website'))

    # Contract addresses
    for m in re.finditer(r'0x[a-fA-F0-9]{40}', text):
        addr = m.group()
        if addr not in seen:
            seen.add(addr)
            assets.append(Asset(target=addr, asset_type='smart_contract'))

    # Domains
    for m in re.finditer(r'(?:\*\.)?[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?', text):
        domain = m.group()
        if domain not in seen and len(domain) > 6 and not is_fp(domain):
            if not domain.endswith(('.js', '.css', '.png', '.jpg', '.gif', '.svg')):
                seen.add(domain)
                assets.append(Asset(target=domain, asset_type='domain'))

    return assets

def clean(text: str) -> str:
    return ' '.join(text.split()).strip()

# ============================================================================
# PLATFORM EXTRACTORS
# ============================================================================

def extract_immunefi(soup: BeautifulSoup, html: str, url: str) -> ProgramScope:
    scope = ProgramScope(platform='immunefi', url=url)
    name = soup.find('h1') or soup.find('title')
    scope.program_name = clean(name.get_text()).split('|')[0].strip() if name else ""

    # Markdown divs
    for div in soup.find_all('div', class_=re.compile(r'Markdown-module|markdown|prose|bounty-module', re.I)):
        scope.assets.extend(extract_targets(div.get_text(separator='\n', strip=True)))

    # Headers
    for h in soup.find_all(['h2', 'h3', 'h4', 'span']):
        ht = h.get_text(strip=True).lower()
        if any(k in ht for k in ['assets', 'scope', 'in scope', 'mainnet', 'testnet', 'contract']):
            p = h.find_parent(['section', 'div', 'article'])
            if p:
                for a in extract_targets(p.get_text(separator='\n', strip=True)):
                    a.in_scope = 'out' not in ht and 'not' not in ht
                    scope.assets.append(a)

    # Contracts from full page
    for c in set(re.findall(r'0x[a-fA-F0-9]{40}', html)):
        scope.assets.append(Asset(target=c, asset_type='smart_contract'))

    # GitHub repos
    for u in set(re.findall(r'https?://github\.com/[^\s<>"\'\)\]\,]+', html)):
        if not is_fp(u):
            scope.assets.append(Asset(target=u, asset_type='repository'))

    scope.assets = dedupe(scope.assets)
    scope.extraction_method = 'immunefi_markdown'
    scope.status = 'success' if scope.assets else 'partial'
    return scope

def extract_rxyz(soup: BeautifulSoup, html: str, url: str) -> ProgramScope:
    scope = ProgramScope(platform='rxyz', url=url)
    name = soup.find('h1') or soup.find('title')
    scope.program_name = clean(name.get_text()).split('|')[0].strip() if name else ""

    inc = soup.find('div', class_=re.compile(r'program-assets-in-scope', re.I))
    if inc:
        for a in extract_targets(inc.get_text(separator='\n', strip=True)):
            a.in_scope = True
            scope.assets.append(a)

    out = soup.find(string=re.compile(r'Out Of Scope', re.I))
    if out:
        p = out.find_parent('div')
        if p:
            for a in extract_targets(p.get_text(separator='\n', strip=True)):
                a.in_scope = False
                scope.assets.append(a)

    scope.assets = dedupe(scope.assets)
    scope.extraction_method = 'rxyz_structured'
    scope.status = 'success' if scope.assets else 'partial'
    return scope

def extract_gobugfree(soup: BeautifulSoup, html: str, url: str) -> ProgramScope:
    scope = ProgramScope(platform='gobugfree', url=url)
    name = soup.find('h1') or soup.find('title')
    scope.program_name = clean(name.get_text()).split('|')[0].strip() if name else ""

    in_sec, out_sec = None, None
    for h in soup.find_all(['h2', 'h3', 'h4']):
        t = h.get_text(strip=True).lower()
        if 'in scope' in t and 'not' not in t:
            e = h.find_next_sibling()
            while e and e.name not in ['h2', 'h3', 'h4']:
                if e.name in ['div', 'section', 'ul']:
                    in_sec = e
                    break
                e = e.find_next_sibling()
        elif 'not in scope' in t or 'out of scope' in t:
            e = h.find_next_sibling()
            while e and e.name not in ['h2', 'h3', 'h4']:
                if e.name in ['div', 'section', 'ul']:
                    out_sec = e
                    break
                e = e.find_next_sibling()

    if in_sec:
        for a in extract_targets(in_sec.get_text(separator='\n', strip=True)):
            a.in_scope = True
            scope.assets.append(a)
    if out_sec:
        for a in extract_targets(out_sec.get_text(separator='\n', strip=True)):
            a.in_scope = False
            scope.assets.append(a)

    scope.assets = dedupe(scope.assets)
    scope.extraction_method = 'gobugfree_headers'
    scope.status = 'success' if scope.assets else 'partial'
    return scope

def extract_standoff365(soup: BeautifulSoup, html: str, url: str) -> ProgramScope:
    scope = ProgramScope(platform='standoff365', url=url)
    name = soup.find('h1') or soup.find('title')
    scope.program_name = clean(name.get_text()).split('|')[0].strip() if name else ""

    for md in soup.find_all('div', class_=re.compile(r'markdown', re.I)):
        text = md.get_text(separator='\n', strip=True)
        if any(k in text for k in ['http', '0x', '.com', '.io', '.xyz', '.ru']):
            scope.assets.extend(extract_targets(text))

    if not scope.assets:
        scope.assets = extract_targets(html)

    scope.assets = dedupe(scope.assets)
    scope.extraction_method = 'standoff365_markdown'
    scope.status = 'success' if scope.assets else 'partial'
    return scope

def extract_bizon(soup: BeautifulSoup, html: str, url: str) -> ProgramScope:
    scope = ProgramScope(platform='bizon', url=url)
    name = soup.find('h1') or soup.find('title')
    scope.program_name = clean(name.get_text()).split('|')[0].strip() if name else ""
    scope.assets = extract_targets(html)
    scope.assets = dedupe(scope.assets)
    scope.extraction_method = 'bizon_regex'
    scope.status = 'success' if scope.assets else 'partial'
    return scope

def extract_cantina(soup: BeautifulSoup, html: str, url: str) -> ProgramScope:
    scope = ProgramScope(platform='cantina', url=url)
    name = soup.find('h1') or soup.find('title')
    scope.program_name = clean(name.get_text()).split('|')[0].strip() if name else ""

    for div in soup.find_all('div', class_=re.compile(r'markdown|prose', re.I)):
        text = div.get_text(separator='\n', strip=True)
        if any(k in text.lower() for k in ['scope', 'contract', '0x', 'https']):
            scope.assets.extend(extract_targets(text))

    for link in soup.find_all('a', href=re.compile(r'github\.com|gitlab', re.I)):
        href = link.get('href', '')
        if href:
            scope.assets.append(Asset(target=href, asset_type='repository'))

    for c in set(re.findall(r'0x[a-fA-F0-9]{40}', html)):
        scope.assets.append(Asset(target=c, asset_type='smart_contract'))

    scope.assets = dedupe(scope.assets)
    scope.extraction_method = 'cantina_markdown'
    scope.status = 'success' if scope.assets else 'partial'
    return scope

def extract_compass(soup: BeautifulSoup, html: str, url: str) -> ProgramScope:
    scope = ProgramScope(platform='compass', url=url)
    name = soup.find('h1') or soup.find('title')
    scope.program_name = clean(name.get_text()).split('|')[0].strip() if name else ""

    found = False
    for elem in soup.find_all(['section', 'div', 'article']):
        text = elem.get_text(separator='\n', strip=True)
        fl = ' '.join(text.split('\n')[:3]).lower()
        if any(k in fl for k in ['scope', 'target', 'asset', 'domain', 'in scope', 'bounty', 'program']):
            found = True
            scope.assets.extend(extract_targets(text))

    if not found:
        main = soup.find('main') or soup.find('article')
        if main:
            scope.assets = extract_targets(main.get_text(separator='\n', strip=True))

    scope.assets = dedupe(scope.assets)
    scope.extraction_method = 'compass_structured'
    scope.status = 'success' if scope.assets else 'partial'
    return scope

def extract_bugbase(soup: BeautifulSoup, html: str, url: str) -> ProgramScope:
    scope = ProgramScope(platform='bugbase', url=url)
    name = soup.find('h1') or soup.find('title')
    scope.program_name = clean(name.get_text()).split('|')[0].strip() if name else ""

    for tag in ['table', 'ul', 'ol']:
        for elem in soup.find_all(tag, class_=re.compile(r'scope|target|asset|domain', re.I)):
            scope.assets.extend(extract_targets(elem.get_text(separator='\n', strip=True)))

    for h in soup.find_all(['h2', 'h3', 'h4']):
        ht = h.get_text(strip=True).lower()
        if any(k in ht for k in ['scope', 'target', 'in scope', 'asset']):
            p = h.find_parent(['section', 'div', 'article'])
            if p:
                scope.assets.extend(extract_targets(p.get_text(separator='\n', strip=True)))

    for script in soup.find_all('script', type='application/json'):
        try:
            scope.assets.extend(extract_targets(json.dumps(json.loads(script.string))))
        except:
            pass

    scope.assets = dedupe(scope.assets)
    scope.extraction_method = 'bugbase_multi'
    scope.status = 'success' if scope.assets else 'partial'
    return scope

def extract_sherlock(soup: BeautifulSoup, html: str, url: str) -> ProgramScope:
    scope = ProgramScope(platform='sherlock', url=url)
    name = soup.find('h1') or soup.find('title')
    scope.program_name = clean(name.get_text()).split('|')[0].strip() if name else ""

    for sec in soup.find_all(['section', 'div'], class_=re.compile(r'scope|contest|audit|bounty', re.I)):
        scope.assets.extend(extract_targets(sec.get_text(separator='\n', strip=True)))

    for link in soup.find_all('a', href=re.compile(r'github\.com', re.I)):
        href = link.get('href', '')
        if href:
            scope.assets.append(Asset(target=href, asset_type='repository'))

    for c in set(re.findall(r'0x[a-fA-F0-9]{40}', html)):
        scope.assets.append(Asset(target=c, asset_type='smart_contract'))

    scope.assets = dedupe(scope.assets)
    scope.extraction_method = 'sherlock_contest'
    scope.status = 'success' if scope.assets else 'partial'
    return scope

def extract_spa(soup: BeautifulSoup, html: str, url: str, platform: str) -> ProgramScope:
    """For pure JS SPAs that need Selenium."""
    scope = ProgramScope(platform=platform, url=url)
    name = soup.find('h1') or soup.find('title')
    scope.program_name = clean(name.get_text()).split('|')[0].strip() if name else ""

    if len(html) < 3000:
        scope.status = 'needs_selenium'
        scope.error_message = 'JS SPA shell - run with Selenium enabled'
        return scope

    scope.assets = extract_targets(html)
    scope.assets = dedupe(scope.assets)
    scope.extraction_method = 'spa_regex'
    scope.status = 'success' if scope.assets else 'partial'
    return scope

def dedupe(assets: List[Asset]) -> List[Asset]:
    seen, result = set(), []
    for a in assets:
        key = (a.target.lower(), a.in_scope)
        if key not in seen:
            seen.add(key)
            result.append(a)
    return result

EXTRACTORS = {
    'immunefi': extract_immunefi,
    'rxyz': extract_rxyz,
    'gobugfree': extract_gobugfree,
    'standoff365': extract_standoff365,
    'bizon': extract_bizon,
    'cantina': extract_cantina,
    'compass': extract_compass,
    'bugbase': extract_bugbase,
    'sherlock': extract_sherlock,
    'issuehunt': lambda s, h, u: extract_spa(s, h, u, 'issuehunt'),
    'bugrap': lambda s, h, u: extract_spa(s, h, u, 'bugrap'),
    'inspectiv': lambda s, h, u: extract_spa(s, h, u, 'inspectiv'),
}

# ============================================================================
# CORE SCRAPER
# ============================================================================

class BugBountyScraper:
    def __init__(self, config: Config = None):
        self.config = config or CONFIG
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })
        self.results: List[ProgramScope] = []
        self.results_lock = Lock()
        self.domain_last: Dict[str, float] = {}
        self.domain_lock = Lock()
        self.selenium = SeleniumManager()
        self.logger = logging.getLogger('scraper')
        self.outdir = Path(self.config.output_dir)
        self.outdir.mkdir(exist_ok=True)

    def _rate_limit(self, url: str):
        domain = urllib.parse.urlparse(url).netloc
        with self.domain_lock:
            last = self.domain_last.get(domain, 0)
            elapsed = time.time() - last
            if elapsed < self.config.request_delay:
                time.sleep(self.config.request_delay - elapsed)
            self.domain_last[domain] = time.time()

    def _fetch(self, url: str) -> Tuple[str, int]:
        for attempt in range(self.config.retry_attempts):
            try:
                self._rate_limit(url)
                r = self.session.get(url, timeout=self.config.request_timeout, allow_redirects=True)
                if r.status_code == 200:
                    return r.text, r.status_code
            except Exception:
                if attempt < self.config.retry_attempts - 1:
                    time.sleep(self.config.retry_delay * (attempt + 1))
        return "", 0

    def scrape_single(self, url: str) -> ProgramScope:
        platform = detect_platform(url)
        self.logger.info(f"[{platform}] {url}")

        html, status = self._fetch(url)

        # Selenium fallback for tiny responses
        if status == 200 and len(html) < 3000 and self.config.use_selenium and SELENIUM_AVAILABLE:
            self.logger.info(f"  Trying Selenium for {platform}...")
            html, status = self.selenium.fetch(url)
            if html:
                status = 200

        scope = ProgramScope(url=url, platform=platform)
        scope.http_status = status

        if status != 200 or not html:
            scope.status = 'failed'
            scope.error_message = f"HTTP {status}"
            return scope

        try:
            soup = BeautifulSoup(html, 'html.parser')
            extractor = EXTRACTORS.get(platform, lambda s, h, u: extract_spa(s, h, u, platform or 'unknown'))
            extracted = extractor(soup, html, url)
            scope.program_name = extracted.program_name
            scope.assets = extracted.assets
            scope.extraction_method = extracted.extraction_method
            scope.status = extracted.status
            scope.error_message = extracted.error_message
            self.logger.info(f"  -> {len(scope.assets)} assets ({scope.extraction_method})")
        except Exception as e:
            scope.status = 'failed'
            scope.error_message = str(e)
            self.logger.exception(f"Extraction failed")

        return scope

    def scrape_all(self, urls: List[str], progress=None) -> List[ProgramScope]:
        self.results = []
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {executor.submit(self.scrape_single, url): url for url in urls}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    result = future.result()
                    with self.results_lock:
                        self.results.append(result)
                    if progress:
                        progress(len(self.results), len(urls), result)
                except Exception as e:
                    self.logger.error(f"Error for {url}: {e}")
                    with self.results_lock:
                        self.results.append(ProgramScope(url=url, status='failed', error_message=str(e)))
        self._save()
        return self.results

    def _save(self):
        # JSON
        with open(self.outdir / 'report.json', 'w') as f:
            json.dump({
                'generated': time.strftime('%Y-%m-%d %H:%M:%S'),
                'programs': [r.to_dict() for r in self.results],
                'summary': {p: {'count': sum(1 for r in self.results if r.platform == p),
                               'assets': sum(len(r.assets) for r in self.results if r.platform == p)}
                           for p in set(r.platform for r in self.results)}
            }, f, indent=2)

        # CSV
        with open(self.outdir / 'assets.csv', 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['Platform', 'Program', 'Target', 'Type', 'In Scope', 'URL'])
            for p in self.results:
                for a in p.assets:
                    w.writerow([p.platform, p.program_name, a.target, a.asset_type, 'Yes' if a.in_scope else 'No', p.url])

        # TXT targets list
        targets = sorted({a.target for p in self.results for a in p.assets if a.in_scope})
        with open(self.outdir / 'in_scope_targets.txt', 'w') as f:
            for t in targets:
                f.write(f"{t}\n")

        self.logger.info(f"Saved to {self.outdir}")

    def close(self):
        self.selenium.close()

# ============================================================================
# CLI
# ============================================================================

def setup_logging(verbose: bool):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[logging.FileHandler('scraper.log'), logging.StreamHandler()]
    )

def load_urls(path: str) -> List[str]:
    urls = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and 'bugbounty.ch' not in line.lower():
                urls.append(line.split('|')[0].strip())
    return urls

def print_progress(current: int, total: int, result: ProgramScope):
    pct = (current / total) * 100
    icon = 'OK' if result.status == 'success' else 'FAIL' if result.status == 'failed' else 'SEL'
    print(f"[{current}/{total}] {pct:.0f}% {icon:4} {result.platform:12} | {result.program_name[:30]:30} | {len(result.assets)} assets")

def main():
    parser = argparse.ArgumentParser(description='Bug Bounty Scope Extractor v4.1')
    parser.add_argument('-i', '--input', default='programs.txt', help='Input file')
    parser.add_argument('-u', '--url', help='Single URL')
    parser.add_argument('-o', '--output', default='bug_bounty_results')
    parser.add_argument('-w', '--workers', type=int, default=6)
    parser.add_argument('--no-selenium', action='store_true')
    parser.add_argument('--screenshots', action='store_true')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--delay', type=float, default=1.0)
    args = parser.parse_args()

    CONFIG.max_workers = args.workers
    CONFIG.use_selenium = not args.no_selenium
    CONFIG.output_dir = args.output
    CONFIG.verbose = args.verbose
    CONFIG.request_delay = args.delay
    CONFIG.screenshots = args.screenshots

    setup_logging(args.verbose)
    logger = logging.getLogger('main')
    logger.info("=== Bug Bounty Scope Extractor v4.1 ===")

    urls = [args.url] if args.url else load_urls(args.input)
    logger.info(f"Loaded {len(urls)} URLs")

    scraper = BugBountyScraper(CONFIG)
    t0 = time.time()
    results = scraper.scrape_all(urls, progress=print_progress)
    elapsed = time.time() - t0

    ok = sum(1 for r in results if r.status == 'success')
    fail = sum(1 for r in results if r.status == 'failed')
    need_sel = sum(1 for r in results if r.status == 'needs_selenium')
    assets = sum(len(r.assets) for r in results)

    logger.info(f"Done in {elapsed:.1f}s | OK:{ok} Fail:{fail} Selenium-needed:{need_sel} Assets:{assets}")
    scraper.close()

if __name__ == '__main__':
    main()
