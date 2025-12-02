"""
Advanced Tooling Layer
Comprehensive security testing toolkit

Features:
- Web crawlers (intelligent spidering)
- Fuzzers (input mutation, protocol fuzzing)
- Taint analysis engines
- Dynamic instrumentation
- Custom security tools integration
"""
import re
import json
import random
import string
import subprocess
import requests
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from enum import Enum
import time


class FuzzingStrategy(Enum):
    """Fuzzing strategies"""
    RANDOM = "random"
    MUTATION = "mutation"
    GENERATION = "generation"
    SMART = "smart"  # AI-guided
    PROTOCOL = "protocol"  # Protocol-aware


class CrawlerMode(Enum):
    """Web crawler modes"""
    PASSIVE = "passive"  # Read-only
    ACTIVE = "active"  # Interactive (forms, clicks)
    AGGRESSIVE = "aggressive"  # Test all inputs


@dataclass
class CrawledEndpoint:
    """Discovered endpoint"""
    url: str = ""
    method: str = "GET"
    parameters: Dict[str, Any] = None
    headers: Dict[str, str] = None
    cookies: Dict[str, str] = None
    forms: List[Dict[str, Any]] = None
    authentication_required: bool = False
    rate_limited: bool = False

    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}
        if self.headers is None:
            self.headers = {}
        if self.cookies is None:
            self.cookies = {}
        if self.forms is None:
            self.forms = []


@dataclass
class FuzzResult:
    """Fuzzing test result"""
    test_case: str = ""
    payload: str = ""
    status_code: int = 0
    response_time: float = 0.0
    response_size: int = 0
    error_detected: bool = False
    error_type: str = ""
    error_message: str = ""
    interesting: bool = False  # Anomalous behavior


class IntelligentWebCrawler:
    """
    Intelligent web crawler with security focus

    Features:
    - Smart URL discovery
    - Form detection and analysis
    - API endpoint enumeration
    - JavaScript parsing
    - Authentication handling
    - Rate limiting awareness
    """

    def __init__(self, base_url: str, mode: CrawlerMode = CrawlerMode.PASSIVE):
        self.base_url = base_url
        self.mode = mode
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: List[CrawledEndpoint] = []
        self.session = requests.Session()
        self.max_depth = 5
        self.max_pages = 1000

    def crawl(self, start_url: Optional[str] = None,
             auth_token: Optional[str] = None) -> List[CrawledEndpoint]:
        """
        Start crawling from base URL or specific start URL

        Args:
            start_url: Starting URL (default: base_url)
            auth_token: Authentication token if required

        Returns:
            List of discovered endpoints
        """
        if start_url is None:
            start_url = self.base_url

        # Setup authentication
        if auth_token:
            self.session.headers['Authorization'] = f'Bearer {auth_token}'

        # Start crawling
        self._crawl_recursive(start_url, depth=0)

        return self.discovered_endpoints

    def _crawl_recursive(self, url: str, depth: int):
        """Recursively crawl website"""
        if depth > self.max_depth or len(self.visited_urls) >= self.max_pages:
            return

        if url in self.visited_urls:
            return

        # Mark as visited
        self.visited_urls.add(url)

        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)

            # Extract endpoint information
            endpoint = self._extract_endpoint_info(url, response)
            self.discovered_endpoints.append(endpoint)

            # Extract links
            links = self._extract_links(response.text, url)

            # Extract forms
            forms = self._extract_forms(response.text, url)
            endpoint.forms = forms

            # Extract API endpoints from JavaScript
            api_endpoints = self._extract_api_endpoints(response.text)
            for api_url in api_endpoints:
                api_full_url = urljoin(url, api_url)
                if api_full_url not in self.visited_urls:
                    self._crawl_recursive(api_full_url, depth + 1)

            # Crawl discovered links
            for link in links:
                full_url = urljoin(url, link)
                if self._is_same_domain(full_url):
                    self._crawl_recursive(full_url, depth + 1)

        except Exception as e:
            print(f"[!] Error crawling {url}: {e}")

    def _extract_endpoint_info(self, url: str, response: requests.Response) -> CrawledEndpoint:
        """Extract endpoint information"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        return CrawledEndpoint(
            url=url,
            method='GET',
            parameters={k: v[0] if len(v) == 1 else v for k, v in params.items()},
            headers=dict(response.request.headers),
            cookies=dict(response.cookies),
            authentication_required=response.status_code == 401
        )

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract all links from HTML"""
        # Simple regex-based extraction
        link_pattern = r'<a\s+(?:[^>]*?\s+)?href=(["\'])(.*?)\1'
        links = re.findall(link_pattern, html)
        return [link[1] for link in links]

    def _extract_forms(self, html: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML"""
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, html, re.DOTALL | re.IGNORECASE)

        for form_html in form_matches:
            # Extract action
            action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            action = action_match.group(1) if action_match else base_url

            # Extract method
            method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else 'GET'

            # Extract inputs
            input_pattern = r'<input[^>]*>'
            inputs = []
            for input_html in re.findall(input_pattern, form_html, re.IGNORECASE):
                name_match = re.search(r'name=["\']([^"\']+)["\']', input_html, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']+)["\']', input_html, re.IGNORECASE)

                if name_match:
                    inputs.append({
                        'name': name_match.group(1),
                        'type': type_match.group(1) if type_match else 'text'
                    })

            forms.append({
                'action': urljoin(base_url, action),
                'method': method,
                'inputs': inputs
            })

        return forms

    def _extract_api_endpoints(self, content: str) -> List[str]:
        """Extract API endpoints from JavaScript"""
        # Common API patterns
        patterns = [
            r'["\']/(api|v1|v2|graphql|rest)/[^"\']*["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[get|post]+\(["\']([^"\']+)["\']',
            r'\.ajax\(\s*\{[^}]*url:\s*["\']([^"\']+)["\']'
        ]

        endpoints = set()
        for pattern in patterns:
            matches = re.findall(pattern, content)
            endpoints.update(matches)

        return list(endpoints)

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to same domain"""
        base_domain = urlparse(self.base_url).netloc
        url_domain = urlparse(url).netloc
        return base_domain == url_domain


class AdvancedFuzzer:
    """
    Advanced fuzzing engine

    Features:
    - Multiple fuzzing strategies
    - Smart payload generation
    - Mutation-based fuzzing
    - Protocol-aware fuzzing
    - Anomaly detection
    """

    def __init__(self, strategy: FuzzingStrategy = FuzzingStrategy.SMART):
        self.strategy = strategy
        self.payloads: List[str] = []
        self.results: List[FuzzResult] = []
        self.baseline_response: Optional[requests.Response] = None

    def fuzz_endpoint(self, endpoint: CrawledEndpoint,
                     parameter: str,
                     max_iterations: int = 100) -> List[FuzzResult]:
        """
        Fuzz specific parameter of endpoint

        Args:
            endpoint: Target endpoint
            parameter: Parameter to fuzz
            max_iterations: Maximum fuzzing iterations

        Returns:
            List of fuzzing results
        """
        # Get baseline response
        self._establish_baseline(endpoint)

        # Generate payloads based on strategy
        payloads = self._generate_payloads(max_iterations)

        # Execute fuzzing
        for i, payload in enumerate(payloads):
            result = self._execute_fuzz_test(endpoint, parameter, payload, i)
            self.results.append(result)

            # Check for interesting results
            if result.interesting:
                print(f"[+] Interesting result: {result.test_case}")

        return self.results

    def fuzz_all_parameters(self, endpoint: CrawledEndpoint,
                           max_iterations_per_param: int = 50) -> Dict[str, List[FuzzResult]]:
        """Fuzz all parameters of endpoint"""
        all_results = {}

        for param in endpoint.parameters.keys():
            print(f"[*] Fuzzing parameter: {param}")
            results = self.fuzz_endpoint(endpoint, param, max_iterations_per_param)
            all_results[param] = results

        return all_results

    def _establish_baseline(self, endpoint: CrawledEndpoint):
        """Establish baseline response for comparison"""
        try:
            if endpoint.method == 'GET':
                self.baseline_response = requests.get(
                    endpoint.url,
                    params=endpoint.parameters,
                    timeout=10
                )
            elif endpoint.method == 'POST':
                self.baseline_response = requests.post(
                    endpoint.url,
                    data=endpoint.parameters,
                    timeout=10
                )
        except Exception as e:
            print(f"[!] Failed to establish baseline: {e}")

    def _generate_payloads(self, count: int) -> List[str]:
        """Generate fuzzing payloads based on strategy"""
        if self.strategy == FuzzingStrategy.RANDOM:
            return self._generate_random_payloads(count)
        elif self.strategy == FuzzingStrategy.MUTATION:
            return self._generate_mutation_payloads(count)
        elif self.strategy == FuzzingStrategy.GENERATION:
            return self._generate_generation_payloads(count)
        elif self.strategy == FuzzingStrategy.SMART:
            return self._generate_smart_payloads(count)
        else:
            return self._generate_random_payloads(count)

    def _generate_random_payloads(self, count: int) -> List[str]:
        """Generate random payloads"""
        payloads = []
        for _ in range(count):
            length = random.randint(1, 1000)
            payload = ''.join(random.choices(string.printable, k=length))
            payloads.append(payload)
        return payloads

    def _generate_mutation_payloads(self, count: int) -> List[str]:
        """Generate mutation-based payloads"""
        base_payloads = [
            "test",
            "admin",
            "user@example.com",
            "12345",
            "<script>alert(1)</script>",
            "' OR '1'='1",
            "../../../etc/passwd"
        ]

        payloads = []
        for _ in range(count):
            base = random.choice(base_payloads)
            mutated = self._mutate_payload(base)
            payloads.append(mutated)

        return payloads

    def _generate_generation_payloads(self, count: int) -> List[str]:
        """Generate payloads from scratch"""
        # Security-focused payload generation
        payloads = []

        # SQL Injection
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "' UNION SELECT NULL--",
            "1'; DROP TABLE users--"
        ]

        # XSS
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'-alert('XSS')-'",
        ]

        # Command Injection
        cmd_payloads = [
            "; ls -la",
            "| whoami",
            "& cat /etc/passwd",
            "`id`",
            "$(whoami)"
        ]

        # Path Traversal
        path_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]

        # LDAP Injection
        ldap_payloads = [
            "*)(uid=*))(|(uid=*",
            "admin*)((|userPassword=*",
            "*)(objectClass=*"
        ]

        all_payloads = sql_payloads + xss_payloads + cmd_payloads + path_payloads + ldap_payloads

        # Return random selection
        return random.choices(all_payloads, k=min(count, len(all_payloads)))

    def _generate_smart_payloads(self, count: int) -> List[str]:
        """Generate AI-guided smart payloads"""
        # Combine multiple strategies
        payloads = []
        payloads.extend(self._generate_generation_payloads(count // 2))
        payloads.extend(self._generate_mutation_payloads(count // 2))
        return payloads[:count]

    def _mutate_payload(self, payload: str) -> str:
        """Mutate payload using various techniques"""
        mutations = [
            lambda p: p + random.choice(string.printable),  # Append random char
            lambda p: random.choice(string.printable) + p,  # Prepend random char
            lambda p: p * random.randint(2, 10),  # Repeat
            lambda p: p.upper(),  # Uppercase
            lambda p: p.lower(),  # Lowercase
            lambda p: p[::-1],  # Reverse
            lambda p: p.replace('a', 'A'),  # Case swap
            lambda p: p + '\x00' * random.randint(1, 10),  # Add null bytes
        ]

        mutation = random.choice(mutations)
        return mutation(payload)

    def _execute_fuzz_test(self, endpoint: CrawledEndpoint,
                          parameter: str, payload: str, test_id: int) -> FuzzResult:
        """Execute single fuzz test"""
        result = FuzzResult(test_case=f"fuzz_{test_id}", payload=payload)

        # Prepare parameters
        params = endpoint.parameters.copy()
        params[parameter] = payload

        try:
            start_time = time.time()

            if endpoint.method == 'GET':
                response = requests.get(endpoint.url, params=params, timeout=10)
            elif endpoint.method == 'POST':
                response = requests.post(endpoint.url, data=params, timeout=10)
            else:
                response = requests.request(endpoint.method, endpoint.url, data=params, timeout=10)

            end_time = time.time()

            # Record results
            result.status_code = response.status_code
            result.response_time = end_time - start_time
            result.response_size = len(response.content)

            # Detect anomalies
            result.interesting = self._is_interesting_response(response)

            # Detect errors
            if response.status_code >= 500:
                result.error_detected = True
                result.error_type = "Server Error"
            elif self._detect_error_patterns(response.text):
                result.error_detected = True
                result.error_type = "Application Error"

        except Exception as e:
            result.error_detected = True
            result.error_type = "Exception"
            result.error_message = str(e)

        return result

    def _is_interesting_response(self, response: requests.Response) -> bool:
        """Check if response is interesting (anomalous)"""
        if self.baseline_response is None:
            return False

        # Compare with baseline
        status_diff = response.status_code != self.baseline_response.status_code
        size_diff = abs(len(response.content) - len(self.baseline_response.content)) > 100
        time_diff = False  # TODO: Track response time differences

        return status_diff or size_diff or time_diff

    def _detect_error_patterns(self, response_text: str) -> bool:
        """Detect error patterns in response"""
        error_patterns = [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_',
            r'valid MySQL result',
            r'PostgreSQL.*ERROR',
            r'Warning.*pg_',
            r'Microsoft OLE DB Provider for SQL Server',
            r'Unclosed quotation mark',
            r'SQLSTATE',
            r'Syntax error.*MySQL',
            r'java\.sql\.SQLException',
            r'Oracle error',
            r'ORA-\d+',
            r'DB2 SQL error',
            r'Traceback \(most recent call last\)',
            r'Exception in thread',
            r'Error: .*Exception',
            r'Fatal error',
            r'<b>Warning</b>:',
            r'<b>Fatal error</b>:',
        ]

        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False


class TaintAnalysisEngine:
    """
    Taint analysis engine for tracking data flow

    Tracks tainted data from sources to sinks
    """

    def __init__(self):
        self.taint_sources: List[str] = []
        self.taint_sinks: List[str] = []
        self.data_flows: List[Dict[str, Any]] = []

    def analyze_code(self, code: str, language: str) -> List[Dict[str, Any]]:
        """
        Analyze code for taint flows

        Args:
            code: Source code to analyze
            language: Programming language

        Returns:
            List of taint flow violations
        """
        violations = []

        # Define sources and sinks based on language
        if language == 'python':
            sources = [
                'request.GET', 'request.POST', 'request.args',
                'request.form', 'request.cookies', 'input()'
            ]
            sinks = [
                'execute(', 'eval(', 'exec(', 'os.system(',
                'subprocess.', 'render_template_string('
            ]
        elif language == 'javascript':
            sources = [
                'req.query', 'req.body', 'req.params',
                'req.cookies', 'location.search', 'document.URL'
            ]
            sinks = [
                'eval(', 'innerHTML', 'document.write(',
                'setTimeout(', 'setInterval(', 'Function('
            ]
        else:
            sources = []
            sinks = []

        # Simple taint tracking
        for source in sources:
            if source in code:
                # Check if data flows to sink
                for sink in sinks:
                    if sink in code:
                        # TODO: More sophisticated flow analysis
                        violations.append({
                            'source': source,
                            'sink': sink,
                            'description': f'Potentially tainted data from {source} flows to {sink}',
                            'severity': 'HIGH'
                        })

        return violations


class ToolingOrchestrator:
    """
    Orchestrator for all security testing tools

    Manages:
    - Web crawling
    - Fuzzing campaigns
    - Taint analysis
    - Custom tool integration
    """

    def __init__(self):
        self.crawler: Optional[IntelligentWebCrawler] = None
        self.fuzzer: Optional[AdvancedFuzzer] = None
        self.taint_engine = TaintAnalysisEngine()
        self.results: Dict[str, Any] = {}

    def run_full_web_test(self, target_url: str,
                         crawl_mode: CrawlerMode = CrawlerMode.ACTIVE,
                         fuzz_strategy: FuzzingStrategy = FuzzingStrategy.SMART,
                         max_fuzz_iterations: int = 50) -> Dict[str, Any]:
        """
        Run complete web application security test

        Args:
            target_url: Target web application URL
            crawl_mode: Crawler mode (passive/active/aggressive)
            fuzz_strategy: Fuzzing strategy
            max_fuzz_iterations: Max fuzzing iterations per parameter

        Returns:
            Comprehensive test results
        """
        print(f"[*] Starting full web test of: {target_url}")

        # 1. Crawl website
        print("[*] Phase 1: Crawling...")
        self.crawler = IntelligentWebCrawler(target_url, crawl_mode)
        endpoints = self.crawler.crawl()
        print(f"[+] Discovered {len(endpoints)} endpoints")

        # 2. Fuzz discovered endpoints
        print("[*] Phase 2: Fuzzing...")
        self.fuzzer = AdvancedFuzzer(fuzz_strategy)
        fuzz_results = {}

        for endpoint in endpoints[:10]:  # Limit to first 10 endpoints
            if endpoint.parameters:
                print(f"[*] Fuzzing: {endpoint.url}")
                results = self.fuzzer.fuzz_all_parameters(endpoint, max_fuzz_iterations)
                fuzz_results[endpoint.url] = results

        # 3. Compile results
        self.results = {
            'target': target_url,
            'crawl_results': {
                'total_endpoints': len(endpoints),
                'endpoints': [asdict(e) for e in endpoints]
            },
            'fuzz_results': {
                'total_tests': sum(len(results) for results in fuzz_results.values()),
                'interesting_results': sum(
                    1 for url_results in fuzz_results.values()
                    for param_results in url_results.values()
                    for result in param_results
                    if result.interesting
                ),
                'errors_found': sum(
                    1 for url_results in fuzz_results.values()
                    for param_results in url_results.values()
                    for result in param_results
                    if result.error_detected
                )
            }
        }

        print("[+] Full web test completed!")
        return self.results

    def execute_custom_tool(self, tool_name: str, args: List[str]) -> Dict[str, Any]:
        """
        Execute custom security tool

        Supports: curl, python scripts, custom binaries
        """
        try:
            result = subprocess.run(
                [tool_name] + args,
                capture_output=True,
                text=True,
                timeout=300
            )

            return {
                'tool': tool_name,
                'exit_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'success': result.returncode == 0
            }
        except Exception as e:
            return {
                'tool': tool_name,
                'error': str(e),
                'success': False
            }
