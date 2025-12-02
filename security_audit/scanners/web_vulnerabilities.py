"""
Web application vulnerability scanner
Detects common OWASP Top 10 vulnerabilities
"""
import re
from typing import List, Dict, Any

from ..core.scanner import BaseScanner, Finding, Severity


class WebVulnerabilityScanner(BaseScanner):
    """Scanner for web application vulnerabilities"""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self._init_patterns()

    def get_name(self) -> str:
        return "Web Vulnerability Scanner"

    def get_description(self) -> str:
        return "Detects common web application vulnerabilities (OWASP Top 10)"

    def _init_patterns(self):
        """Initialize vulnerability detection patterns"""

        # SQL Injection patterns
        self.sql_injection_patterns = [
            # Direct SQL concatenation
            (r'(execute|exec|query|rawQuery)\s*\(\s*["\'].*?\+.*?["\']',
             'Direct string concatenation in SQL query'),
            (r'(execute|exec|query|rawQuery)\s*\(\s*f["\'].*?\{.*?\}.*?["\']',
             'F-string interpolation in SQL query'),
            (r'(SELECT|INSERT|UPDATE|DELETE|DROP).*?(\+|\.format|\%s)',
             'String formatting in SQL statement'),
            (r'cursor\.execute\s*\(\s*["\'].*?(\+|\.format|\%)',
             'Unsafe SQL execution in Python'),
            (r'db\.(query|exec|raw)\s*\(["\'].*?(\+|\$\{)',
             'Unsafe SQL query construction'),
            # Django ORM
            (r'\.raw\s*\(\s*["\'].*?(\+|\.format|%)',
             'Django raw SQL with string formatting'),
            (r'\.extra\s*\(\s*where\s*=\s*\[["\'].*?(\+|\.format)',
             'Django .extra() with unsafe where clause'),
            # SQLAlchemy
            (r'session\.execute\s*\(\s*["\'].*?(\+|\.format|%)',
             'SQLAlchemy execute with string formatting'),
            (r'text\s*\(\s*f["\']',
             'SQLAlchemy text() with f-string'),
            # PHP/MySQL
            (r'mysql_(query|real_query)\s*\([^)]*?\$_(GET|POST|REQUEST)',
             'MySQL query with user input'),
            (r'mysqli.*?query\s*\([^)]*?(\$_(GET|POST|REQUEST)|\$_)',
             'MySQLi query with user input'),
            (r'\$wpdb->query\s*\([^)]*?(\$_(GET|POST)|\.)',
             'WordPress SQL query with concatenation'),
            # Node.js/JavaScript
            (r'(query|execute)\s*\(\s*[`"\'][^`"\']*?\$\{',
             'SQL query with template literal interpolation'),
            (r'sequelize\.query\s*\([^)]*?[\+\$]',
             'Sequelize raw query with string concat'),
            # Java/JDBC
            (r'Statement.*?execute(Query|Update)\s*\([^)]*?\+',
             'JDBC Statement with string concatenation'),
            (r'createQuery\s*\([^)]*?\+',
             'JPA createQuery with string concatenation'),
        ]

        # XSS patterns
        self.xss_patterns = [
            # JavaScript DOM manipulation
            (r'innerHTML\s*=\s*(?!["\']\s*["\']\s*$)',
             'Potentially unsafe innerHTML assignment - XSS risk'),
            (r'outerHTML\s*=',
             'Potentially unsafe outerHTML assignment - XSS risk'),
            (r'document\.write\s*\(',
             'Use of document.write - XSS risk'),
            (r'document\.writeln\s*\(',
             'Use of document.writeln - XSS risk'),
            (r'\.insertAdjacentHTML\s*\(',
             'insertAdjacentHTML - verify input sanitization'),
            # React
            (r'dangerouslySetInnerHTML\s*=\s*\{\{',
             'Use of dangerouslySetInnerHTML in React - XSS risk'),
            # Vue.js
            (r'v-html\s*=',
             'Use of v-html in Vue.js - XSS risk'),
            # Angular
            (r'\[innerHTML\]\s*=',
             'Angular innerHTML binding - XSS risk'),
            (r'bypassSecurityTrust(Html|Script|Style|Url)',
             'Angular security bypass - XSS risk'),
            # Template engines
            (r'\{\{\{.*?\}\}\}',
             'Unescaped template output (Handlebars/Mustache)'),
            (r'<%=\s*(?!.*?h\()',
             'Unescaped output in ERB/EJS templates'),
            (r'\{\{\s*(?!.*?\|\s*escape)',
             'Potentially unescaped Jinja2/Django template'),
            # PHP
            (r'echo\s+\$_(GET|POST|REQUEST|COOKIE)',
             'Direct output of user input in PHP - XSS'),
            (r'print\s+\$_(GET|POST|REQUEST|COOKIE)',
             'Direct print of user input in PHP - XSS'),
            (r'<\?=\s*\$_(GET|POST|REQUEST|COOKIE)',
             'PHP short echo with user input - XSS'),
            # Python
            (r'print\s*\(\s*request\.(GET|POST|args|form|cookies)',
             'Direct output of user input in Python'),
            (r'HttpResponse\s*\([^)]*?request\.(GET|POST)',
             'Django HttpResponse with user input - XSS risk'),
            (r'render_template_string\s*\([^)]*?request\.',
             'Flask render_template_string with user input - SSTI/XSS'),
            # Java/JSP
            (r'<%=\s*request\.getParameter',
             'JSP output of request parameter - XSS'),
            (r'out\.println\s*\([^)]*?request\.getParameter',
             'Java servlet output with request param - XSS'),
        ]

        # Command Injection patterns
        self.command_injection_patterns = [
            (r'(exec|system|shell_exec|passthru|popen)\s*\(\s*\$_(GET|POST|REQUEST)',
             'Command injection via user input (PHP)'),
            (r'(os\.system|os\.popen|subprocess\.call|subprocess\.run|eval)\s*\([^)]*?(request\.|input\()',
             'Command injection risk (Python)'),
            (r'child_process\.(exec|spawn)\s*\([^)]*?(req\.|process\.argv)',
             'Command injection risk (Node.js)'),
            (r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*?(request\.|getParameter)',
             'Command injection risk (Java)'),
        ]

        # Path Traversal patterns
        self.path_traversal_patterns = [
            (r'(open|file_get_contents|readfile|include|require)\s*\(\s*\$_(GET|POST|REQUEST)',
             'Path traversal risk (PHP)'),
            (r'(open|read)\s*\([^)]*?(request\.|input\()',
             'Path traversal risk (Python)'),
            (r'fs\.(readFile|readFileSync|createReadStream)\s*\([^)]*?(req\.|params)',
             'Path traversal risk (Node.js)'),
            (r'\.\.[\\/]',
             'Potential path traversal sequence'),
        ]

        # SSRF patterns
        self.ssrf_patterns = [
            (r'(requests\.get|requests\.post|urllib\.request|http\.request)\s*\([^)]*?(request\.|input\()',
             'SSRF risk - user-controlled URL (Python)'),
            (r'(axios|fetch|http\.get|http\.request)\s*\([^)]*?(req\.|params)',
             'SSRF risk - user-controlled URL (JavaScript)'),
            (r'(curl_exec|file_get_contents)\s*\(\s*\$_(GET|POST|REQUEST)',
             'SSRF risk - user-controlled URL (PHP)'),
        ]

        # XXE patterns
        self.xxe_patterns = [
            # Java patterns
            (r'DocumentBuilder.*?setFeature.*?false',
             'XML parser without XXE protection'),
            (r'XMLReader.*?setFeature.*?false',
             'XML reader without XXE protection'),
            (r'SAXParser.*?(?!setFeature)',
             'SAX parser without explicit XXE protection'),
            # Python lxml patterns
            (r'etree\.XMLParser\s*\([^)]*?(resolve_entities\s*=\s*True|load_dtd\s*=\s*True)',
             'XML parser with dangerous settings - XXE risk'),
            (r'etree\.parse\s*\([^)]*?\)(?!.*XMLParser)',
             'lxml parse without explicit parser - XXE risk'),
            (r'etree\.fromstring\s*\([^)]*?\)(?!.*XMLParser)',
             'lxml fromstring without parser - XXE risk'),
            # Python xml.etree
            (r'xml\.etree\.ElementTree\.(parse|fromstring|XML)\s*\(',
             'Unsafe XML parsing with xml.etree - XXE risk'),
            # Python defusedxml check
            (r'from xml\.|import xml\.(?!.*defusedxml)',
             'Using xml module instead of defusedxml - XXE risk'),
            # PHP patterns
            (r'simplexml_load_(string|file)\s*\([^)]*?\)(?!.*LIBXML_NOENT.*false)',
             'PHP simplexml without XXE protection'),
            (r'new DOMDocument\s*\(\s*\)(?!.*loadXML.*LIBXML_NOENT)',
             'PHP DOMDocument without XXE protection'),
            # Node.js patterns
            (r'new\s+DOMParser\s*\(\s*\)\.parseFromString',
             'DOMParser in Node.js - potential XXE'),
            (r'libxmljs\.parseXml\s*\([^)]*?\)(?!.*noent.*false)',
             'Node.js libxmljs without XXE protection'),
        ]

        # CSRF patterns
        self.csrf_patterns = [
            (r'@(app\.route|route)\s*\([^)]*?methods\s*=\s*\[[^]]*?["\']POST["\']',
             'POST endpoint without visible CSRF protection'),
            (r'app\.(post|put|delete)\s*\(',
             'State-changing endpoint without visible CSRF protection'),
        ]

        # Insecure Deserialization
        self.deserialization_patterns = [
            (r'pickle\.loads?\s*\(',
             'Use of pickle (insecure deserialization risk)'),
            (r'yaml\.load\s*\([^)]*?\)',
             'Use of yaml.load without SafeLoader'),
            (r'unserialize\s*\(',
             'Use of unserialize (PHP)'),
            (r'JSON\.parse\s*\([^)]*?(req\.|params)',
             'JSON parsing of user input without validation'),
        ]

        # Weak Cryptography
        self.weak_crypto_patterns = [
            (r'hashlib\.(md5|sha1)\s*\(',
             'Use of weak hashing algorithm (MD5/SHA1)'),
            (r'(md5|sha1)\s*\(',
             'Use of weak hashing algorithm'),
            (r'DES|RC4|RC2',
             'Use of weak encryption algorithm'),
            (r'random\s*\(',
             'Use of non-cryptographic random'),
        ]

        # Hardcoded Credentials
        self.hardcoded_creds_patterns = [
            (r'(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']',
             'Hardcoded password'),
            (r'(api_key|apikey|api-key)\s*=\s*["\'][^"\']+["\']',
             'Hardcoded API key'),
            (r'(secret|secret_key)\s*=\s*["\'][^"\']{8,}["\']',
             'Hardcoded secret'),
        ]

        # Insecure HTTP usage
        self.insecure_http_patterns = [
            (r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)',
             'Use of insecure HTTP protocol'),
        ]

        # Code Injection patterns (CWE-94) - NEW 2024
        self.code_injection_patterns = [
            (r'\beval\s*\(',
             'Use of eval() - code injection risk'),
            (r'\bexec\s*\(',
             'Use of exec() - code injection risk'),
            (r'Function\s*\(\s*[^)]*?(req\.|request\.|params)',
             'Dynamic function creation with user input'),
            (r'eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
             'Eval with user input (PHP)'),
            (r'assert\s*\([^)]*?(request\.|input\()',
             'Assert with user input'),
        ]

        # Clickjacking patterns (CWE-1021) - NEW 2024
        self.clickjacking_patterns = [
            (r'@app\.route.*?(?!.*X-Frame-Options)',
             'Missing X-Frame-Options header'),
            (r'(res|response)\.send\s*\((?!.*X-Frame-Options)',
             'Response without clickjacking protection'),
        ]

        # Improper Authorization / IDOR patterns (CWE-863) - NEW 2024
        self.authorization_patterns = [
            (r'(User|Account|Profile)\.objects\.get\s*\(\s*id\s*=\s*(request\.|params)',
             'Potential IDOR - direct object reference without authorization check'),
            (r'findById\s*\(\s*(req\.|request\.|params)',
             'Direct object access without authorization'),
            (r'WHERE\s+id\s*=\s*\$_(GET|POST|REQUEST)',
             'SQL query with user-controlled ID without authorization'),
        ]

        # Information Disclosure patterns (CWE-200) - NEW 2024
        self.info_disclosure_patterns = [
            (r'(print|echo|console\.log)\s*\([^)]*?(password|secret|token|api_key)',
             'Logging sensitive information'),
            (r'error_reporting\s*\(\s*E_ALL',
             'Verbose error reporting enabled'),
            (r'(app\.run|app\.listen)\s*\([^)]*?debug\s*[=:]\s*True',
             'Debug mode enabled in production'),
            (r'traceback\.print_exc\s*\(',
             'Full stack trace exposure'),
        ]

        # Resource Exhaustion / DoS patterns (CWE-400) - NEW 2024
        self.resource_exhaustion_patterns = [
            (r'while\s*\(\s*True\s*\)(?!.*break)',
             'Infinite loop without break condition'),
            (r'(recursion|recursive).*?(?!.*limit)',
             'Unbounded recursion'),
            (r'\.read\s*\(\s*\)(?!.*size|.*limit)',
             'Reading entire file without size limit'),
            (r'for.*?in.*?request\.(files|data)(?!.*limit)',
             'Processing user input without rate limiting'),
        ]

        # Mass Assignment patterns - NEW 2024
        self.mass_assignment_patterns = [
            (r'\.save\s*\(\s*request\.(POST|data|json)',
             'Mass assignment without field filtering'),
            (r'\.update\s*\(\s*\*\*request\.(POST|data|json)',
             'Unsafe mass update from user input'),
            (r'Object\.assign\s*\([^,]+,\s*(req\.body|request\.data)',
             'Mass assignment in JavaScript'),
        ]

        # JWT Security Issues - NEW 2024
        self.jwt_patterns = [
            (r'jwt\.decode\s*\([^)]*?verify\s*=\s*False',
             'JWT signature verification disabled'),
            (r'algorithm\s*=\s*["\']none["\']',
             'JWT with "none" algorithm'),
            (r'jwt\.encode\s*\([^)]*?HS256.*?(secret|key)\s*=\s*["\'][^"\']{1,8}["\']',
             'Weak JWT secret key'),
        ]

        # Privilege Management patterns (CWE-269) - NEW 2024
        self.privilege_patterns = [
            (r'(sudo|su|runas)\s+',
             'Privilege elevation command'),
            (r'chmod\s+777',
             'Overly permissive file permissions'),
            (r'setuid\s*\(\s*0\s*\)',
             'Setting UID to root'),
            (r'is_admin\s*=\s*True(?!.*if|.*check)',
             'Hardcoded admin privilege'),
        ]

        # Open Redirect patterns - NEW 2024
        self.open_redirect_patterns = [
            (r'(redirect|location)\s*\(\s*(request\.|params|req\.)',
             'Open redirect - user-controlled URL'),
            (r'header\s*\(\s*["\']Location:.*?\$_(GET|POST|REQUEST)',
             'Open redirect in PHP'),
        ]

        # Server-Side Template Injection (SSTI) - NEW 2024
        self.ssti_patterns = [
            (r'render_template_string\s*\([^)]*?(request\.|input\()',
             'Template injection risk (Flask)'),
            (r'Template\s*\([^)]*?(req\.|request\.|params)',
             'Server-side template injection risk'),
        ]

        # === ADVANCED PATTERNS FROM PROFESSIONAL SAST TOOLS (2025) ===

        # HTTP Request Without Timeout (from Bandit B113)
        self.timeout_patterns = [
            (r'requests\.(get|post|put|delete|patch|head|options)\s*\([^)]*?\)(?!.*timeout)',
             'HTTP request without timeout - can cause indefinite hang'),
            (r'requests\.(get|post|put|delete|patch|head|options)\s*\([^)]*?timeout\s*=\s*None',
             'HTTP request with timeout=None - can hang indefinitely'),
            (r'httpx\.(get|post|put|delete|patch|head|options|request|stream)\s*\([^)]*?\)(?!.*timeout)',
             'HTTPX request without timeout'),
            (r'urllib\.request\.urlopen\s*\([^)]*?\)(?!.*timeout)',
             'URLopen without timeout'),
        ]

        # Archive Extraction Vulnerabilities (from Bandit B202)
        self.archive_extraction_patterns = [
            # Python tarfile
            (r'tarfile\.extractall\s*\(\s*\)',
             'Tarfile extraction without validation - path traversal risk'),
            (r'tarfile\.extractall\s*\([^)]*?\)',
             'Tarfile extraction - verify path traversal protection'),
            (r'tarfile\.extract\s*\([^)]*?\)(?!.*safe|.*filter)',
             'Tarfile extract without validation'),
            # Python zipfile
            (r'zipfile\.extractall\s*\(',
             'ZIP extraction - verify path traversal protection'),
            (r'zipfile\.ZipFile.*?\.extract\s*\([^)]*?\)(?!.*safe)',
             'ZIP extract without path validation'),
            # Python shutil
            (r'shutil\.unpack_archive\s*\(',
             'Archive unpacking - check for path traversal'),
            # Java
            (r'ZipEntry.*?getName\(\)(?!.*\.contains\(["\']\.\.["\']\)|.*startsWith)',
             'Java ZIP entry without path validation'),
            (r'ZipInputStream.*?getNextEntry\(\)(?!.*sanitize|.*validate)',
             'Java ZIP extraction without validation'),
            # Node.js
            (r'(extract-zip|unzipper|tar).*?extract\(',
             'Node.js archive extraction - verify validation'),
            (r'fs\.createWriteStream.*?entry\.fileName',
             'Direct file write from archive entry'),
            # PHP
            (r'ZipArchive.*?extractTo\(',
             'PHP ZIP extraction - check path traversal'),
            (r'PharData.*?extractTo\(',
             'PHP Phar extraction - verify validation'),
        ]

        # Jinja2 Template Security (from Bandit B701)
        self.jinja2_patterns = [
            (r'jinja2\.Environment\s*\([^)]*?autoescape\s*=\s*False',
             'Jinja2 autoescape disabled - XSS risk'),
            (r'jinja2\.Environment\s*\(\s*\)(?!.*autoescape)',
             'Jinja2 Environment without autoescape (defaults to False)'),
            (r'from_string\s*\([^)]*?\)(?!.*autoescape)',
             'Jinja2 template from_string without autoescape'),
        ]

        # Shell Injection Advanced (from Bandit patterns)
        self.shell_advanced_patterns = [
            (r'subprocess\.(Popen|call|run|check_output)\s*\([^)]*?shell\s*=\s*True',
             'Subprocess with shell=True - command injection risk'),
            (r'os\.system\s*\([^)]*?(\+|\.format|f["\']|%)',
             'os.system with formatted string - high risk shell injection'),
            (r'subprocess\.Popen\s*\(\s*["\'](?!.*[\\/])',
             'Subprocess with relative path - PATH manipulation risk'),
        ]

        # TOCTOU Race Conditions (from CVE-2025 patterns)
        self.race_condition_patterns = [
            # Python patterns
            (r'os\.access\s*\([^)]*?\)',
             'TOCTOU risk - os.access() check (use open() instead)'),
            (r'os\.path\.exists\s*\([^)]*?\)',
             'TOCTOU risk - exists() check before operation'),
            (r'os\.path\.isfile\s*\([^)]*?\)',
             'TOCTOU risk - isfile() check before operation'),
            (r'os\.path\.isdir\s*\([^)]*?\)',
             'TOCTOU risk - isdir() check before operation'),
            (r'os\.stat\s*\([^)]*?\)',
             'TOCTOU risk - stat() check before operation'),
            (r'Path\([^)]*?\)\.(exists|is_file|is_dir)\(\)',
             'TOCTOU risk with pathlib check'),
            # PHP patterns
            (r'file_exists\s*\([^)]*?\)',
             'TOCTOU risk - PHP file_exists() before operation'),
            (r'is_file\s*\([^)]*?\)',
             'TOCTOU risk - PHP is_file() check'),
            (r'is_readable\s*\([^)]*?\)',
             'TOCTOU risk - PHP is_readable() check'),
            # Java patterns
            (r'\.exists\(\).*?new FileInputStream',
             'TOCTOU risk - Java exists() before FileInputStream'),
            (r'Files\.exists\s*\([^)]*?\)',
             'TOCTOU risk - Java Files.exists() check'),
            # Node.js patterns
            (r'fs\.existsSync\s*\([^)]*?\)',
             'TOCTOU risk - Node.js existsSync() check'),
            (r'fs\.statSync\s*\([^)]*?\)',
             'TOCTOU risk - Node.js statSync() check'),
        ]

        # Unsafe Deserialization Advanced
        self.deserialization_advanced_patterns = [
            (r'pickle\.loads?\s*\([^)]*?(request\.|input\(|sys\.stdin)',
             'Pickle deserialization from untrusted source'),
            (r'yaml\.(?:load|full_load)\s*\([^)]*?\)(?!.*Loader\s*=\s*yaml\.SafeLoader)',
             'YAML load without SafeLoader - code execution risk'),
            (r'marshal\.loads?\s*\(',
             'Marshal deserialization - code execution risk'),
            (r'shelve\.open\s*\([^)]*?(request\.|input\()',
             'Shelve with user-controlled path'),
        ]

        # Regex DoS (ReDoS) patterns
        self.redos_patterns = [
            # Nested quantifiers (e.g., (a+)+, (a*)*)
            (r're\.compile\s*\(["\'][^"\']*?(\(.*?\)\+|\(.*?\)\*){2,}',
             'Potential ReDoS - nested quantifiers in regex'),
            (r're\.(match|search|findall)\s*\(["\'][^"\']*?(\(.*?\)\+.*?\+|\(.*?\)\*.*?\*)',
             'ReDoS risk - catastrophic backtracking pattern'),
            # Alternation with overlapping patterns (e.g., (a|a)*,  (a|ab)*)
            (r're\.(compile|match|search|findall)\s*\(["\'][^"\']*?\([^)]*?\|[^)]*?\)[\*\+]',
             'Potential ReDoS - alternation with quantifier'),
            # Repetition followed by same character (e.g., a+a, a*a)
            (r're\.(compile|match|search|findall)\s*\(["\'][^"\']*?([a-z])[\*\+][\'"]?\1',
             'ReDoS risk - repetition followed by same character'),
            # JavaScript regex patterns
            (r'new RegExp\s*\(["\'][^"\']*?(\(.*?\)[\*\+]){2,}',
             'JavaScript ReDoS - nested quantifiers'),
            (r'/[^/]*?(\(.*?\)[\*\+]){2,}[^/]*?/[gmi]*',
             'JavaScript regex literal with ReDoS pattern'),
            # PHP preg patterns
            (r'preg_(match|match_all|replace)\s*\(["\'][^"\']*?(\(.*?\)[\*\+]){2,}',
             'PHP ReDoS - nested quantifiers in regex'),
            # Dangerous patterns: (.*)*,  (.+)+,  (a+)+,  (a|a?)+
            (r'[\(\[]\.[\*\+][\)\]][\*\+]',
             'Critical ReDoS - nested .* or .+'),
        ]

        # Integer Overflow/Underflow
        self.integer_overflow_patterns = [
            (r'int\s*\(\s*(request\.|input\()',
             'Unchecked integer conversion from user input'),
            (r'range\s*\(\s*int\s*\((request\.|input\()',
             'Range with user-controlled integer - potential DoS'),
            (r'\w+\s*\*\s*int\s*\((request\.|input\()',
             'Multiplication with user-controlled integer'),
        ]

        # File Upload Vulnerabilities (from Semgrep patterns)
        self.file_upload_patterns = [
            (r'request\.(files|FILES)\s*\[.*?\]\.save\s*\(',
             'File upload without validation'),
            (r'request\.(files|FILES).*?(?!.*allowed_extensions|.*ALLOWED_EXTENSIONS)',
             'File upload without extension check'),
            (r'werkzeug\..*?save\s*\([^)]*?\)(?!.*secure_filename)',
             'File save without secure_filename()'),
            (r'request\.FILES.*?\.save\s*\([^)]*?\)(?!.*UploadedFile)',
             'Django file upload without proper handling'),
        ]

        # XXE Advanced patterns
        self.xxe_advanced_patterns = [
            (r'etree\.XMLParser\s*\([^)]*?\)(?!.*resolve_entities\s*=\s*False)',
             'XML parser without resolve_entities=False'),
            (r'xml\.dom\.minidom\.parse\s*\([^)]*?(request\.|input\()',
             'Minidom parsing user-controlled XML'),
            (r'xml\.sax\.parse\s*\([^)]*?\)(?!.*setFeature)',
             'SAX parser without security features'),
        ]

        # Cryptography Weaknesses (from Bandit)
        self.crypto_advanced_patterns = [
            (r'Crypto\.Cipher\.DES\.',
             'Use of DES encryption - broken algorithm'),
            (r'Crypto\.Cipher\.ARC[24]\.',
             'Use of RC2/RC4 - weak stream cipher'),
            (r'cryptography\.hazmat\.primitives\.ciphers\.modes\.ECB',
             'ECB mode encryption - pattern leaking'),
            (r'random\.random\s*\(\s*\).*?(password|token|key|secret)',
             'Weak random for cryptographic use'),
            (r'os\.urandom\s*\(\s*[1-9]\s*\)',
             'Insufficient entropy - less than 16 bytes'),
        ]

        # SQL Injection Advanced (from Semgrep)
        self.sql_advanced_patterns = [
            (r'raw\s*\(["\'].*?%s.*?["\'].*?\%',
             'Django raw() with % formatting'),
            (r'RawSQL\s*\(["\'].*?\+',
             'Django RawSQL with concatenation'),
            (r'cursor\.execute.*?\.format\s*\(',
             'SQL with .format() - injection risk'),
            (r'f["\']SELECT.*?\{[^}]*?\}.*?["\']',
             'SQL in f-string - injection risk'),
        ]

        # LDAP Injection
        self.ldap_injection_patterns = [
            (r'ldap\.search.*?\([^)]*?(\+|\.format|f["\'])',
             'LDAP search with user input - injection risk'),
            (r'ldap_search\s*\([^)]*?(request\.|input\()',
             'LDAP search with unvalidated input'),
        ]

        # NoSQL Injection
        self.nosql_injection_patterns = [
            (r'db\.collection\.find\s*\(\s*\{[^}]*?(request\.|params|req\.)',
             'MongoDB query with user input - injection risk'),
            (r'\.where\s*\(["\'].*?(\+|\$\{)',
             'NoSQL where clause with string concatenation'),
        ]

        # Prototype Pollution (JavaScript)
        self.prototype_pollution_patterns = [
            (r'Object\.assign\s*\(\s*\{\s*\}\s*,\s*(req\.|request\.|params)',
             'Prototype pollution via Object.assign'),
            (r'\.\.\.req\.(body|query|params)',
             'Spread operator with user input - pollution risk'),
            (r'__proto__\s*=',
             'Direct __proto__ assignment'),
        ]

        # Server-Side Template Injection (SSTI)
        self.ssti_patterns = [
            # Python
            (r'render_template_string\s*\([^)]*?(request\.|input\(|\+|\.format)',
             'SSTI in Flask render_template_string'),
            (r'Template\s*\([^)]*?(request\.|input\(|\+)',
             'SSTI risk in Jinja2 Template()'),
            (r'from_string\s*\([^)]*?(request\.|input\()',
             'SSTI in Jinja2 from_string()'),
            # Node.js
            (r'(pug|jade|ejs|handlebars)\.compile\s*\([^)]*?(req\.|params)',
             'SSTI in Node.js template compilation'),
            (r'eval\s*\([^)]*?(`.*?\$\{|template)',
             'Template injection via eval'),
            # Java
            (r'Velocity\.evaluate\s*\([^)]*?request\.getParameter',
             'SSTI in Apache Velocity'),
            (r'FreeMarker.*?Template.*?process\s*\([^)]*?request',
             'SSTI in FreeMarker'),
        ]

        # Insecure Direct Object Reference (IDOR)
        self.idor_patterns = [
            # Direct ID usage from request
            (r'(find|get|findOne|findById)\s*\([^)]*?(request\.|req\.|params|args)\.(id|userId|accountId)',
             'Potential IDOR - direct object access via user ID'),
            (r'(DELETE|UPDATE|SELECT).*?WHERE.*?(request\.|req\.)(id|userId)',
             'SQL IDOR - user-controlled ID in query'),
            (r'\.filter\s*\(\s*id\s*=\s*(request\.|req\.)',
             'ORM IDOR - filtering by user-controlled ID'),
            # File access
            (r'(open|read|download).*?(request\.|req\.|params)\.(file|filename|path)',
             'IDOR in file access - missing authorization check'),
        ]

        # API Security Issues
        self.api_security_patterns = [
            # Missing rate limiting
            (r'@(app\.route|router\.(get|post))\s*\([^\)]*?\)(?!.*@limiter)',
             'API endpoint without rate limiting'),
            # Mass assignment
            (r'(User|Model)\.objects\.create\s*\(\s*\*\*request\.',
             'Mass assignment vulnerability - use explicit fields'),
            (r'new (User|Model)\s*\(\s*req\.body\s*\)',
             'Mass assignment via req.body'),
            # Verbose errors
            (r'(except|catch).*?(\n.*?){0,3}(print|console\.log|echo).*?(e\.|error|exception)',
             'Verbose error exposure - information disclosure'),
        ]

        # Hardcoded Secrets Detection (Enhanced)
        self.hardcoded_secrets_enhanced_patterns = [
            # API Keys with patterns
            (r'["\'][0-9a-zA-Z]{32,}["\']',
             'Potential hardcoded API key or token'),
            # AWS
            (r'AKIA[0-9A-Z]{16}',
             'AWS Access Key ID'),
            # Private keys
            (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
             'Hardcoded private key'),
            # Generic secrets
            (r'(secret|password|passwd|pwd)\s*=\s*["\'][^"\']{8,}["\']',
             'Hardcoded password or secret'),
        ]

    def scan(self, file_path: str, content: str, file_type: str) -> List[Finding]:
        """Scan file for web vulnerabilities"""
        findings = []
        lines = content.splitlines()

        # Check configuration for which checks to run
        checks = self.config.get("checks", {})

        if checks.get("sql_injection", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.sql_injection_patterns,
                "SQL Injection", Severity.CRITICAL,
                "Use parameterized queries or ORM. Never concatenate user input into SQL.",
                "CWE-89", "A03:2021 - Injection"
            ))

        if checks.get("xss", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.xss_patterns,
                "Cross-Site Scripting (XSS)", Severity.HIGH,
                "Escape all user-controlled data before rendering. Use secure templating.",
                "CWE-79", "A03:2021 - Injection"
            ))

        if checks.get("command_injection", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.command_injection_patterns,
                "Command Injection", Severity.CRITICAL,
                "Avoid executing shell commands with user input. Use safe APIs instead.",
                "CWE-78", "A03:2021 - Injection"
            ))

        if checks.get("path_traversal", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.path_traversal_patterns,
                "Path Traversal", Severity.HIGH,
                "Validate and sanitize file paths. Use allowlists for file access.",
                "CWE-22", "A01:2021 - Broken Access Control"
            ))

        if checks.get("ssrf", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.ssrf_patterns,
                "Server-Side Request Forgery (SSRF)", Severity.HIGH,
                "Validate and restrict URLs. Use allowlists for external requests.",
                "CWE-918", "A10:2021 - Server-Side Request Forgery"
            ))

        if checks.get("xxe", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.xxe_patterns,
                "XML External Entity (XXE)", Severity.HIGH,
                "Disable external entity processing in XML parsers.",
                "CWE-611", "A05:2021 - Security Misconfiguration"
            ))

        if checks.get("csrf", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.csrf_patterns,
                "Missing CSRF Protection", Severity.MEDIUM,
                "Implement CSRF tokens for state-changing operations.",
                "CWE-352", "A01:2021 - Broken Access Control"
            ))

        if checks.get("insecure_deserialization", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.deserialization_patterns,
                "Insecure Deserialization", Severity.HIGH,
                "Avoid deserializing untrusted data. Use safe formats like JSON.",
                "CWE-502", "A08:2021 - Software and Data Integrity Failures"
            ))

        if checks.get("weak_crypto", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.weak_crypto_patterns,
                "Weak Cryptography", Severity.MEDIUM,
                "Use strong cryptographic algorithms (e.g., SHA-256, AES-256).",
                "CWE-327", "A02:2021 - Cryptographic Failures"
            ))

        if checks.get("hardcoded_credentials", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.hardcoded_creds_patterns,
                "Hardcoded Credentials", Severity.CRITICAL,
                "Never hardcode credentials. Use environment variables or secure vaults.",
                "CWE-798", "A07:2021 - Identification and Authentication Failures"
            ))

        findings.extend(self._check_patterns(
            file_path, lines, self.insecure_http_patterns,
            "Insecure HTTP", Severity.LOW,
            "Use HTTPS for all external communications.",
            "CWE-319", "A02:2021 - Cryptographic Failures"
        ))

        # NEW 2024 CWE Top 25 patterns
        if checks.get("code_injection", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.code_injection_patterns,
                "Code Injection", Severity.CRITICAL,
                "Never use eval() or exec() with user input. Use safe alternatives.",
                "CWE-94", "A03:2021 - Injection"
            ))

        if checks.get("clickjacking", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.clickjacking_patterns,
                "Clickjacking", Severity.MEDIUM,
                "Add X-Frame-Options: DENY or SAMEORIGIN header to prevent clickjacking.",
                "CWE-1021", "A04:2021 - Insecure Design"
            ))

        if checks.get("authorization", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.authorization_patterns,
                "Improper Authorization (IDOR)", Severity.HIGH,
                "Always verify user authorization before accessing objects. Check ownership.",
                "CWE-863", "A01:2021 - Broken Access Control"
            ))

        if checks.get("info_disclosure", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.info_disclosure_patterns,
                "Information Disclosure", Severity.MEDIUM,
                "Never log sensitive data. Disable debug mode in production.",
                "CWE-200", "A04:2021 - Insecure Design"
            ))

        if checks.get("resource_exhaustion", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.resource_exhaustion_patterns,
                "Resource Exhaustion / DoS", Severity.HIGH,
                "Implement rate limiting, timeouts, and resource constraints.",
                "CWE-400", "A04:2021 - Insecure Design"
            ))

        if checks.get("mass_assignment", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.mass_assignment_patterns,
                "Mass Assignment", Severity.HIGH,
                "Use field whitelisting. Never directly assign user input to models.",
                "CWE-915", "A04:2021 - Insecure Design"
            ))

        if checks.get("jwt_security", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.jwt_patterns,
                "JWT Security Issue", Severity.CRITICAL,
                "Always verify JWT signatures. Use strong secrets (32+ chars). Avoid 'none' algorithm.",
                "CWE-347", "A02:2021 - Cryptographic Failures"
            ))

        if checks.get("privilege_management", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.privilege_patterns,
                "Improper Privilege Management", Severity.HIGH,
                "Follow principle of least privilege. Avoid running as root. Use proper permission checks.",
                "CWE-269", "A01:2021 - Broken Access Control"
            ))

        if checks.get("open_redirect", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.open_redirect_patterns,
                "Open Redirect", Severity.MEDIUM,
                "Validate redirect URLs against whitelist. Never redirect to user-controlled URLs.",
                "CWE-601", "A01:2021 - Broken Access Control"
            ))

        if checks.get("ssti", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.ssti_patterns,
                "Server-Side Template Injection (SSTI)", Severity.CRITICAL,
                "Never pass user input to template engines. Use sandboxed templates.",
                "CWE-94", "A03:2021 - Injection"
            ))

        # === ADVANCED CHECKS FROM PROFESSIONAL SAST TOOLS (2025) ===

        if checks.get("timeout_check", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.timeout_patterns,
                "HTTP Request Without Timeout", Severity.MEDIUM,
                "Always specify timeout parameter to prevent indefinite hangs. Use timeout=30 or similar.",
                "CWE-400", "A04:2021 - Insecure Design"
            ))

        if checks.get("archive_extraction", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.archive_extraction_patterns,
                "Unsafe Archive Extraction", Severity.HIGH,
                "Validate archive members before extraction. Use filter='data' for tarfile or validate paths.",
                "CWE-22", "A01:2021 - Broken Access Control"
            ))

        if checks.get("jinja2_security", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.jinja2_patterns,
                "Jinja2 XSS Risk", Severity.HIGH,
                "Always use autoescape=True or select_autoescape() in Jinja2 Environment.",
                "CWE-79", "A03:2021 - Injection"
            ))

        if checks.get("shell_advanced", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.shell_advanced_patterns,
                "Advanced Shell Injection", Severity.CRITICAL,
                "Avoid shell=True. Use subprocess with list arguments and absolute paths.",
                "CWE-78", "A03:2021 - Injection"
            ))

        if checks.get("race_conditions", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.race_condition_patterns,
                "TOCTOU Race Condition", Severity.HIGH,
                "Use atomic file operations. Open files directly without prior existence checks.",
                "CWE-362", "A04:2021 - Insecure Design"
            ))

        if checks.get("deserialization_advanced", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.deserialization_advanced_patterns,
                "Advanced Deserialization Risk", Severity.CRITICAL,
                "Never deserialize untrusted data. Use JSON or safe alternatives to pickle/yaml.load.",
                "CWE-502", "A08:2021 - Software and Data Integrity Failures"
            ))

        if checks.get("redos", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.redos_patterns,
                "Regex DoS (ReDoS)", Severity.MEDIUM,
                "Avoid nested quantifiers in regex. Test regex performance with long inputs.",
                "CWE-1333", "A04:2021 - Insecure Design"
            ))

        if checks.get("integer_overflow", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.integer_overflow_patterns,
                "Integer Overflow Risk", Severity.MEDIUM,
                "Validate and bound integer inputs. Check ranges before arithmetic operations.",
                "CWE-190", "A04:2021 - Insecure Design"
            ))

        if checks.get("file_upload", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.file_upload_patterns,
                "Insecure File Upload", Severity.HIGH,
                "Validate file extensions, use secure_filename(), scan for malware, store outside webroot.",
                "CWE-434", "A04:2021 - Insecure Design"
            ))

        if checks.get("xxe_advanced", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.xxe_advanced_patterns,
                "XML External Entity (XXE) Advanced", Severity.HIGH,
                "Disable external entity resolution: resolve_entities=False, disable DTD processing.",
                "CWE-611", "A05:2021 - Security Misconfiguration"
            ))

        if checks.get("crypto_advanced", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.crypto_advanced_patterns,
                "Advanced Cryptography Weakness", Severity.HIGH,
                "Use AES-256, avoid ECB mode, use secrets module for random, minimum 16 bytes entropy.",
                "CWE-327", "A02:2021 - Cryptographic Failures"
            ))

        if checks.get("sql_advanced", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.sql_advanced_patterns,
                "Advanced SQL Injection", Severity.CRITICAL,
                "Use parameterized queries. Avoid .format(), %, and f-strings in SQL.",
                "CWE-89", "A03:2021 - Injection"
            ))

        if checks.get("ldap_injection", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.ldap_injection_patterns,
                "LDAP Injection", Severity.HIGH,
                "Sanitize and escape LDAP filter inputs. Use parameterized queries.",
                "CWE-90", "A03:2021 - Injection"
            ))

        if checks.get("nosql_injection", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.nosql_injection_patterns,
                "NoSQL Injection", Severity.HIGH,
                "Validate and sanitize inputs. Use query builders, not string concatenation.",
                "CWE-943", "A03:2021 - Injection"
            ))

        if checks.get("prototype_pollution", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.prototype_pollution_patterns,
                "Prototype Pollution", Severity.HIGH,
                "Validate object keys. Avoid Object.assign/spread with user input. Use Object.create(null).",
                "CWE-1321", "A04:2021 - Insecure Design"
            ))

        # === NEW ADVANCED PATTERNS FOR IMPROVED DETECTION ===

        if checks.get("ssti", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.ssti_patterns,
                "Server-Side Template Injection (SSTI)", Severity.CRITICAL,
                "Never pass user input directly to template engines. Use sandboxed templates.",
                "CWE-94", "A03:2021 - Injection"
            ))

        if checks.get("idor", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.idor_patterns,
                "Insecure Direct Object Reference (IDOR)", Severity.HIGH,
                "Implement authorization checks. Verify user owns the requested resource.",
                "CWE-639", "A01:2021 - Broken Access Control"
            ))

        if checks.get("api_security", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.api_security_patterns,
                "API Security Issue", Severity.MEDIUM,
                "Implement rate limiting, input validation, and proper error handling.",
                "CWE-799", "A04:2021 - Insecure Design"
            ))

        if checks.get("hardcoded_secrets_enhanced", True):
            findings.extend(self._check_patterns(
                file_path, lines, self.hardcoded_secrets_enhanced_patterns,
                "Hardcoded Secret or Credential", Severity.CRITICAL,
                "Use environment variables or secret management systems. Never hardcode credentials.",
                "CWE-798", "A02:2021 - Cryptographic Failures"
            ))

        return findings

    def _check_patterns(self, file_path: str, lines: List[str], patterns: List[tuple],
                       title: str, severity: Severity, recommendation: str,
                       cwe_id: str, owasp_category: str) -> List[Finding]:
        """Check content against patterns"""
        findings = []

        for line_num, line in enumerate(lines, start=1):
            for pattern, description in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    finding = Finding(
                        scanner=self.get_name(),
                        severity=severity,
                        title=title,
                        description=description,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_code_snippet(lines, line_num),
                        recommendation=recommendation,
                        cwe_id=cwe_id,
                        owasp_category=owasp_category
                    )
                    findings.append(finding)

        return findings

    def _get_code_snippet(self, lines: List[str], line_num: int, context: int = 2) -> str:
        """Get code snippet with context"""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        snippet_lines = []

        for i in range(start, end):
            prefix = ">>>" if i == line_num - 1 else "   "
            snippet_lines.append(f"{prefix} {i + 1:4d} | {lines[i]}")

        return "\n".join(snippet_lines)
