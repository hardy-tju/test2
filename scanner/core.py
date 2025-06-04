import asyncio
import aiohttp
from aiohttp import ClientSession
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Optional
from colorama import Fore, Style


SQL_PAYLOADS = ["'", "' or '1'='1", "\" or \"1\"=\"1", "'--", "' OR 1=1 --"]
XSS_PAYLOADS = ['<script>alert(1)</script>', '" onmouseover="alert(1)', "<img src=x onerror=alert(1)>"]
CMD_PAYLOADS = [';id', '&&id', '|id']
TRAVERSAL_PAYLOADS = ['../../../../../../etc/passwd', '..\\..\\..\\..\\windows\\win.ini']
LFI_PAYLOADS = ['../../../../../../etc/passwd', '/etc/passwd']
RFI_PAYLOADS = ['http://example.com']

ERROR_PATTERNS = ['SQL syntax', 'mysql_fetch', 'ORA-', 'Warning:']


class VulnerabilityResult:
    def __init__(self, vuln_type: str, url: str, param: str, payload: str, response_text: str):
        self.vuln_type = vuln_type
        self.url = url
        self.param = param
        self.payload = payload
        self.response_text = response_text


class VulnerabilityScanner:
    def __init__(self, targets: List[str], proxy: Optional[str] = None):
        self.targets = targets
        self.proxy = proxy
        self.results: List[VulnerabilityResult] = []

    async def fetch(self, session: ClientSession, url: str, params: Dict[str, Any]) -> str:
        async with session.get(url, params=params, allow_redirects=False) as resp:
            return await resp.text()

    async def test_payloads(self, session: ClientSession, url: str, params: Dict[str, Any], payloads: List[str],
                            vuln_type: str, check_func):
        for param in params:
            for payload in payloads:
                mod_params = params.copy()
                mod_params[param] = payload
                text = await self.fetch(session, url, mod_params)
                if check_func(text, payload):
                    self.results.append(VulnerabilityResult(vuln_type, url, param, payload, text))
                    print(f"{Fore.RED}[!] {vuln_type} on {url} param {param} payload {payload}{Style.RESET_ALL}")

    def check_sqli(self, text: str, payload: str) -> bool:
        lowered = text.lower()
        return any(err.lower() in lowered for err in ERROR_PATTERNS)

    def check_xss(self, text: str, payload: str) -> bool:
        return payload in text

    def check_cmd(self, text: str, payload: str) -> bool:
        return 'uid=' in text or 'gid=' in text

    def check_traversal(self, text: str, payload: str) -> bool:
        return 'root:' in text or 'windows' in text.lower()

    def check_lfi(self, text: str, payload: str) -> bool:
        return 'root:' in text

    def check_rfi(self, text: str, payload: str) -> bool:
        return 'http' in payload and ('<!DOCTYPE html>' in text or '<html' in text)

    async def scan_url(self, session: ClientSession, url: str):
        params = {'test': '1'}
        await self.test_payloads(session, url, params, SQL_PAYLOADS, 'SQL Injection', self.check_sqli)
        await self.test_payloads(session, url, params, XSS_PAYLOADS, 'Reflected XSS', self.check_xss)
        await self.test_payloads(session, url, params, CMD_PAYLOADS, 'Command Injection', self.check_cmd)
        await self.test_payloads(session, url, params, TRAVERSAL_PAYLOADS, 'Directory Traversal', self.check_traversal)
        await self.test_payloads(session, url, params, LFI_PAYLOADS, 'Local File Inclusion', self.check_lfi)
        await self.test_payloads(session, url, params, RFI_PAYLOADS, 'Remote File Inclusion', self.check_rfi)

    async def run(self):
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            for url in self.targets:
                try:
                    await self.scan_url(session, url)
                except Exception as exc:
                    print(f"{Fore.YELLOW}Error scanning {url}: {exc}{Style.RESET_ALL}")

    def generate_report(self) -> str:
        lines = ['# Scan Report\n']
        for r in self.results:
            lines.append(f"## {r.vuln_type} on {r.url}")
            lines.append(f"- Parameter: {r.param}")
            lines.append(f"- Payload: `{r.payload}`")
            snippet = r.response_text[:200].replace('\n', ' ')
            lines.append(f"- Response snippet: `{snippet}`\n")
        return '\n'.join(lines)
