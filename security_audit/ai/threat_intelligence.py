"""
Threat Intelligence & Risk Modeling Module
Implements P.A.S.T.A (Process for Attack Simulation and Threat Analysis) methodology

Features:
- Business context gathering
- Technology stack identification
- Attack surface mapping
- Threat modeling using P.A.S.T.A
- Integration with custom prompts and internal docs
"""
import json
import re
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict


@dataclass
class BusinessContext:
    """Business context information"""
    application_name: str = ""
    business_domain: str = ""  # e.g., "e-commerce", "healthcare", "finance"
    sensitive_data_types: List[str] = None  # e.g., ["PII", "payment cards", "health records"]
    compliance_requirements: List[str] = None  # e.g., ["GDPR", "HIPAA", "PCI-DSS"]
    user_roles: List[str] = None  # e.g., ["admin", "user", "guest"]
    critical_assets: List[str] = None  # e.g., ["customer database", "payment gateway"]

    def __post_init__(self):
        if self.sensitive_data_types is None:
            self.sensitive_data_types = []
        if self.compliance_requirements is None:
            self.compliance_requirements = []
        if self.user_roles is None:
            self.user_roles = []
        if self.critical_assets is None:
            self.critical_assets = []


@dataclass
class TechnologyStack:
    """Technology stack information"""
    languages: List[str] = None  # e.g., ["Python", "JavaScript", "Java"]
    frameworks: List[str] = None  # e.g., ["Django", "React", "Spring Boot"]
    databases: List[str] = None  # e.g., ["PostgreSQL", "MongoDB", "Redis"]
    web_servers: List[str] = None  # e.g., ["Nginx", "Apache"]
    cloud_providers: List[str] = None  # e.g., ["AWS", "Azure", "GCP"]
    third_party_services: List[str] = None  # e.g., ["Stripe", "SendGrid", "Auth0"]

    def __post_init__(self):
        if self.languages is None:
            self.languages = []
        if self.frameworks is None:
            self.frameworks = []
        if self.databases is None:
            self.databases = []
        if self.web_servers is None:
            self.web_servers = []
        if self.cloud_providers is None:
            self.cloud_providers = []
        if self.third_party_services is None:
            self.third_party_services = []


@dataclass
class AttackSurface:
    """Attack surface mapping"""
    entry_points: List[str] = None  # e.g., ["REST API", "Web UI", "Mobile App"]
    authentication_methods: List[str] = None  # e.g., ["JWT", "OAuth2", "Session"]
    data_flows: List[str] = None  # e.g., ["User -> API -> Database"]
    external_integrations: List[str] = None  # e.g., ["Payment Gateway", "Email Service"]
    exposed_services: List[str] = None  # e.g., ["HTTPS:443", "SSH:22"]

    def __post_init__(self):
        if self.entry_points is None:
            self.entry_points = []
        if self.authentication_methods is None:
            self.authentication_methods = []
        if self.data_flows is None:
            self.data_flows = []
        if self.external_integrations is None:
            self.external_integrations = []
        if self.exposed_services is None:
            self.exposed_services = []


@dataclass
class ThreatModel:
    """P.A.S.T.A threat model"""
    stage: str  # P.A.S.T.A stage (1-7)
    threats: List[Dict[str, Any]] = None
    mitigations: List[str] = None
    risk_score: float = 0.0  # 0-10
    likelihood: str = ""  # "Low", "Medium", "High", "Critical"
    impact: str = ""  # "Low", "Medium", "High", "Critical"

    def __post_init__(self):
        if self.threats is None:
            self.threats = []
        if self.mitigations is None:
            self.mitigations = []


class PASTAThreatModeling:
    """
    P.A.S.T.A (Process for Attack Simulation and Threat Analysis) Implementation

    7 Stages:
    1. Define Objectives (DO) - Business context
    2. Define Technical Scope (DTS) - Tech stack
    3. Application Decomposition (AD) - Attack surface
    4. Threat Analysis (TA) - Identify threats
    5. Vulnerability Analysis (VA) - Map vulnerabilities
    6. Attack Modeling (AM) - Simulate attacks
    7. Risk & Impact Analysis (RIA) - Risk scoring
    """

    def __init__(self):
        self.business_context = BusinessContext()
        self.tech_stack = TechnologyStack()
        self.attack_surface = AttackSurface()
        self.threat_models: List[ThreatModel] = []

    def stage1_define_objectives(self, context: Dict[str, Any]) -> BusinessContext:
        """
        Stage 1: Define Objectives (DO)
        Gather business context and security objectives
        """
        self.business_context = BusinessContext(
            application_name=context.get('application_name', 'Unknown'),
            business_domain=context.get('business_domain', ''),
            sensitive_data_types=context.get('sensitive_data_types', []),
            compliance_requirements=context.get('compliance_requirements', []),
            user_roles=context.get('user_roles', []),
            critical_assets=context.get('critical_assets', [])
        )
        return self.business_context

    def stage2_define_technical_scope(self, project_path: str) -> TechnologyStack:
        """
        Stage 2: Define Technical Scope (DTS)
        Identify technology stack from codebase
        """
        tech_stack = TechnologyStack()
        project = Path(project_path)

        # Detect languages
        language_extensions = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.php': 'PHP',
            '.rb': 'Ruby',
            '.go': 'Go',
            '.cs': 'C#',
            '.rs': 'Rust',
            '.kt': 'Kotlin'
        }

        detected_languages = set()
        for ext, lang in language_extensions.items():
            if list(project.rglob(f'*{ext}')):
                detected_languages.add(lang)

        tech_stack.languages = list(detected_languages)

        # Detect frameworks (from common files)
        framework_indicators = {
            'requirements.txt': self._detect_python_frameworks,
            'package.json': self._detect_js_frameworks,
            'pom.xml': self._detect_java_frameworks,
            'composer.json': self._detect_php_frameworks,
            'Gemfile': self._detect_ruby_frameworks,
            'go.mod': self._detect_go_frameworks,
        }

        detected_frameworks = set()
        for indicator_file, detector_func in framework_indicators.items():
            indicator_path = project / indicator_file
            if indicator_path.exists():
                frameworks = detector_func(indicator_path)
                detected_frameworks.update(frameworks)

        tech_stack.frameworks = list(detected_frameworks)

        # Detect databases (from config files and code)
        tech_stack.databases = self._detect_databases(project)

        self.tech_stack = tech_stack
        return tech_stack

    def stage3_application_decomposition(self, project_path: str) -> AttackSurface:
        """
        Stage 3: Application Decomposition (AD)
        Map attack surface - entry points, data flows, integrations
        """
        attack_surface = AttackSurface()
        project = Path(project_path)

        # Detect entry points from routes/controllers
        attack_surface.entry_points = self._detect_entry_points(project)

        # Detect authentication methods
        attack_surface.authentication_methods = self._detect_auth_methods(project)

        # Detect external integrations
        attack_surface.external_integrations = self._detect_external_integrations(project)

        self.attack_surface = attack_surface
        return attack_surface

    def stage4_threat_analysis(self) -> List[ThreatModel]:
        """
        Stage 4: Threat Analysis (TA)
        Identify threats based on STRIDE, OWASP, and context
        """
        threats = []

        # STRIDE threats mapped to business context
        stride_threats = {
            'Spoofing': ['Identity theft', 'Authentication bypass', 'Session hijacking'],
            'Tampering': ['Data manipulation', 'Code injection', 'Man-in-the-middle'],
            'Repudiation': ['Log tampering', 'Transaction denial', 'Audit bypass'],
            'Information Disclosure': ['Data leakage', 'Privacy breach', 'Sensitive info exposure'],
            'Denial of Service': ['Resource exhaustion', 'Service disruption', 'DDoS'],
            'Elevation of Privilege': ['Privilege escalation', 'Authorization bypass', 'Admin takeover']
        }

        for category, threat_list in stride_threats.items():
            for threat_name in threat_list:
                threat = ThreatModel(
                    stage='4-TA',
                    threats=[{
                        'category': category,
                        'name': threat_name,
                        'description': f'{threat_name} targeting {self.business_context.business_domain} application',
                        'cwe': self._map_threat_to_cwe(threat_name)
                    }],
                    likelihood=self._calculate_likelihood(threat_name),
                    impact=self._calculate_impact(threat_name),
                    risk_score=0.0
                )
                threats.append(threat)

        self.threat_models = threats
        return threats

    def stage5_vulnerability_analysis(self, findings: List[Dict[str, Any]]) -> List[ThreatModel]:
        """
        Stage 5: Vulnerability Analysis (VA)
        Map discovered vulnerabilities to threats
        """
        for finding in findings:
            vulnerability_type = finding.get('type', '')
            severity = finding.get('severity', 'MEDIUM')

            # Find matching threat model
            for threat in self.threat_models:
                if self._matches_threat(vulnerability_type, threat):
                    threat.threats.append({
                        'vulnerability': vulnerability_type,
                        'severity': severity,
                        'file': finding.get('file', ''),
                        'line': finding.get('line', 0),
                        'description': finding.get('description', '')
                    })

        return self.threat_models

    def stage6_attack_modeling(self) -> List[Dict[str, Any]]:
        """
        Stage 6: Attack Modeling (AM)
        Simulate attack scenarios and vectors
        """
        attack_scenarios = []

        for threat in self.threat_models:
            if threat.threats:
                scenario = {
                    'threat_category': threat.threats[0].get('category', 'Unknown'),
                    'attack_vector': self._generate_attack_vector(threat),
                    'prerequisites': self._identify_prerequisites(threat),
                    'steps': self._generate_attack_steps(threat),
                    'indicators': self._identify_indicators(threat)
                }
                attack_scenarios.append(scenario)

        return attack_scenarios

    def stage7_risk_impact_analysis(self) -> List[ThreatModel]:
        """
        Stage 7: Risk & Impact Analysis (RIA)
        Calculate risk scores and prioritize
        """
        risk_matrix = {
            ('Critical', 'Critical'): 10.0,
            ('Critical', 'High'): 9.0,
            ('Critical', 'Medium'): 7.5,
            ('High', 'Critical'): 9.0,
            ('High', 'High'): 8.0,
            ('High', 'Medium'): 6.0,
            ('Medium', 'Critical'): 7.0,
            ('Medium', 'High'): 6.0,
            ('Medium', 'Medium'): 5.0,
            ('Low', 'High'): 4.0,
            ('Low', 'Medium'): 3.0,
            ('Low', 'Low'): 2.0,
        }

        for threat in self.threat_models:
            key = (threat.likelihood, threat.impact)
            threat.risk_score = risk_matrix.get(key, 5.0)

        # Sort by risk score (highest first)
        self.threat_models.sort(key=lambda t: t.risk_score, reverse=True)

        return self.threat_models

    def generate_full_report(self) -> Dict[str, Any]:
        """Generate comprehensive P.A.S.T.A threat model report"""
        return {
            'methodology': 'P.A.S.T.A (Process for Attack Simulation and Threat Analysis)',
            'stages': {
                '1_define_objectives': asdict(self.business_context),
                '2_technical_scope': asdict(self.tech_stack),
                '3_attack_surface': asdict(self.attack_surface),
                '4_7_threat_models': [asdict(t) for t in self.threat_models]
            },
            'summary': {
                'total_threats': len(self.threat_models),
                'critical_risks': len([t for t in self.threat_models if t.risk_score >= 9.0]),
                'high_risks': len([t for t in self.threat_models if 7.0 <= t.risk_score < 9.0]),
                'medium_risks': len([t for t in self.threat_models if 5.0 <= t.risk_score < 7.0]),
                'low_risks': len([t for t in self.threat_models if t.risk_score < 5.0])
            }
        }

    # Helper methods

    def _detect_python_frameworks(self, requirements_file: Path) -> List[str]:
        """Detect Python frameworks from requirements.txt"""
        frameworks = []
        content = requirements_file.read_text()

        framework_patterns = {
            'Django': r'(?i)django[>=<]',
            'Flask': r'(?i)flask[>=<]',
            'FastAPI': r'(?i)fastapi[>=<]',
            'Pyramid': r'(?i)pyramid[>=<]',
            'Tornado': r'(?i)tornado[>=<]'
        }

        for framework, pattern in framework_patterns.items():
            if re.search(pattern, content):
                frameworks.append(framework)

        return frameworks

    def _detect_js_frameworks(self, package_file: Path) -> List[str]:
        """Detect JavaScript frameworks from package.json"""
        frameworks = []
        try:
            data = json.loads(package_file.read_text())
            dependencies = {**data.get('dependencies', {}), **data.get('devDependencies', {})}

            framework_mapping = {
                'react': 'React',
                'vue': 'Vue.js',
                'angular': 'Angular',
                'express': 'Express.js',
                'next': 'Next.js',
                'nest': 'NestJS',
                'koa': 'Koa',
                'fastify': 'Fastify'
            }

            for dep_name, framework in framework_mapping.items():
                if dep_name in dependencies:
                    frameworks.append(framework)
        except:
            pass

        return frameworks

    def _detect_java_frameworks(self, pom_file: Path) -> List[str]:
        """Detect Java frameworks from pom.xml"""
        frameworks = []
        content = pom_file.read_text()

        if 'spring-boot' in content or 'spring-framework' in content:
            frameworks.append('Spring Boot')
        if 'jakarta.ee' in content or 'javax.ee' in content:
            frameworks.append('Jakarta EE')
        if 'hibernate' in content:
            frameworks.append('Hibernate')

        return frameworks

    def _detect_php_frameworks(self, composer_file: Path) -> List[str]:
        """Detect PHP frameworks from composer.json"""
        frameworks = []
        try:
            data = json.loads(composer_file.read_text())
            requires = data.get('require', {})

            if 'laravel/framework' in requires:
                frameworks.append('Laravel')
            if 'symfony/symfony' in requires:
                frameworks.append('Symfony')
            if 'codeigniter4/framework' in requires:
                frameworks.append('CodeIgniter')
        except:
            pass

        return frameworks

    def _detect_ruby_frameworks(self, gemfile: Path) -> List[str]:
        """Detect Ruby frameworks from Gemfile"""
        frameworks = []
        content = gemfile.read_text()

        if 'rails' in content:
            frameworks.append('Ruby on Rails')
        if 'sinatra' in content:
            frameworks.append('Sinatra')

        return frameworks

    def _detect_go_frameworks(self, go_mod: Path) -> List[str]:
        """Detect Go frameworks from go.mod"""
        frameworks = []
        content = go_mod.read_text()

        if 'gin-gonic/gin' in content:
            frameworks.append('Gin')
        if 'echo' in content:
            frameworks.append('Echo')
        if 'fiber' in content:
            frameworks.append('Fiber')

        return frameworks

    def _detect_databases(self, project: Path) -> List[str]:
        """Detect databases from config files and code"""
        databases = set()

        # Search for database indicators in config files
        for file_path in project.rglob('*'):
            if file_path.is_file() and file_path.suffix in ['.py', '.js', '.json', '.yml', '.yaml', '.env']:
                try:
                    content = file_path.read_text(errors='ignore').lower()

                    db_indicators = {
                        'postgresql': ['postgresql', 'psycopg2', 'postgres'],
                        'MySQL': ['mysql', 'mariadb'],
                        'MongoDB': ['mongodb', 'pymongo'],
                        'Redis': ['redis'],
                        'SQLite': ['sqlite'],
                        'Oracle': ['oracle', 'cx_oracle'],
                        'SQL Server': ['sqlserver', 'mssql']
                    }

                    for db_name, indicators in db_indicators.items():
                        if any(indicator in content for indicator in indicators):
                            databases.add(db_name)
                except:
                    continue

        return list(databases)

    def _detect_entry_points(self, project: Path) -> List[str]:
        """Detect application entry points"""
        entry_points = set()

        # Look for route definitions, API endpoints, etc.
        route_patterns = [
            r'@app\.route',  # Flask
            r'@app\.(get|post|put|delete)',  # FastAPI
            r'router\.(get|post|put|delete)',  # Express
            r'path\(',  # Django
            r'Route::',  # Laravel
        ]

        for file_path in project.rglob('*'):
            if file_path.is_file() and file_path.suffix in ['.py', '.js', '.ts', '.php']:
                try:
                    content = file_path.read_text(errors='ignore')
                    for pattern in route_patterns:
                        if re.search(pattern, content):
                            entry_points.add('REST API')
                            break
                except:
                    continue

        # Check for web UI
        if list(project.rglob('*.html')):
            entry_points.add('Web UI')

        return list(entry_points)

    def _detect_auth_methods(self, project: Path) -> List[str]:
        """Detect authentication methods"""
        auth_methods = set()

        auth_indicators = {
            'JWT': ['jwt', 'jsonwebtoken'],
            'OAuth2': ['oauth', 'oauth2'],
            'Session': ['session', 'cookie'],
            'Basic Auth': ['basic auth', 'basicauth'],
            'API Key': ['api_key', 'apikey']
        }

        for file_path in project.rglob('*'):
            if file_path.is_file():
                try:
                    content = file_path.read_text(errors='ignore').lower()
                    for method, indicators in auth_indicators.items():
                        if any(indicator in content for indicator in indicators):
                            auth_methods.add(method)
                except:
                    continue

        return list(auth_methods)

    def _detect_external_integrations(self, project: Path) -> List[str]:
        """Detect external service integrations"""
        integrations = set()

        integration_indicators = {
            'Stripe': ['stripe'],
            'PayPal': ['paypal'],
            'SendGrid': ['sendgrid'],
            'Twilio': ['twilio'],
            'AWS': ['boto3', 'aws-sdk'],
            'Azure': ['azure-'],
            'Google Cloud': ['google-cloud', 'gcp']
        }

        for file_path in project.rglob('*'):
            if file_path.is_file():
                try:
                    content = file_path.read_text(errors='ignore').lower()
                    for service, indicators in integration_indicators.items():
                        if any(indicator in content for indicator in indicators):
                            integrations.add(service)
                except:
                    continue

        return list(integrations)

    def _map_threat_to_cwe(self, threat_name: str) -> str:
        """Map threat to CWE ID"""
        threat_cwe_mapping = {
            'Identity theft': 'CWE-287',
            'Authentication bypass': 'CWE-287',
            'Session hijacking': 'CWE-384',
            'Data manipulation': 'CWE-345',
            'Code injection': 'CWE-94',
            'Man-in-the-middle': 'CWE-300',
            'Log tampering': 'CWE-117',
            'Data leakage': 'CWE-200',
            'Privacy breach': 'CWE-359',
            'Sensitive info exposure': 'CWE-200',
            'Resource exhaustion': 'CWE-400',
            'Service disruption': 'CWE-400',
            'DDoS': 'CWE-400',
            'Privilege escalation': 'CWE-269',
            'Authorization bypass': 'CWE-863',
            'Admin takeover': 'CWE-269'
        }
        return threat_cwe_mapping.get(threat_name, 'CWE-Unknown')

    def _calculate_likelihood(self, threat_name: str) -> str:
        """Calculate threat likelihood based on context"""
        # Simplified likelihood calculation
        high_likelihood = ['Authentication bypass', 'Data leakage', 'Sensitive info exposure']
        medium_likelihood = ['Session hijacking', 'Code injection', 'Privilege escalation']

        if threat_name in high_likelihood:
            return 'High'
        elif threat_name in medium_likelihood:
            return 'Medium'
        else:
            return 'Low'

    def _calculate_impact(self, threat_name: str) -> str:
        """Calculate threat impact based on business context"""
        critical_impact = ['Admin takeover', 'Data leakage', 'Privacy breach']
        high_impact = ['Authentication bypass', 'Privilege escalation', 'Data manipulation']

        if threat_name in critical_impact:
            return 'Critical'
        elif threat_name in high_impact:
            return 'High'
        else:
            return 'Medium'

    def _matches_threat(self, vulnerability_type: str, threat: ThreatModel) -> bool:
        """Check if vulnerability matches threat model"""
        # Simple matching logic
        vuln_lower = vulnerability_type.lower()
        for threat_info in threat.threats:
            if isinstance(threat_info, dict):
                threat_name = threat_info.get('name', '').lower()
                if any(word in vuln_lower for word in threat_name.split()):
                    return True
        return False

    def _generate_attack_vector(self, threat: ThreatModel) -> str:
        """Generate attack vector description"""
        if threat.threats:
            category = threat.threats[0].get('category', 'Unknown')
            return f"Attack vector targeting {category} vulnerabilities"
        return "Unknown attack vector"

    def _identify_prerequisites(self, threat: ThreatModel) -> List[str]:
        """Identify attack prerequisites"""
        return [
            "Network access to application",
            "Valid user account (for authenticated attacks)",
            "Knowledge of application structure"
        ]

    def _generate_attack_steps(self, threat: ThreatModel) -> List[str]:
        """Generate attack steps"""
        if threat.threats:
            threat_name = threat.threats[0].get('name', 'Unknown')
            return [
                f"1. Identify {threat_name} vulnerability",
                "2. Craft exploit payload",
                "3. Execute attack",
                "4. Verify successful exploitation"
            ]
        return []

    def _identify_indicators(self, threat: ThreatModel) -> List[str]:
        """Identify compromise indicators"""
        return [
            "Unusual network traffic patterns",
            "Failed authentication attempts",
            "Unauthorized data access",
            "System log anomalies"
        ]


class ThreatIntelligence:
    """
    Main Threat Intelligence interface
    Combines P.A.S.T.A with external threat intelligence feeds
    """

    def __init__(self):
        self.pasta = PASTAThreatModeling()
        self.custom_prompts: List[str] = []
        self.internal_docs: Dict[str, str] = {}

    def analyze_project(self, project_path: str,
                       business_context: Dict[str, Any] = None,
                       findings: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Complete threat intelligence analysis using P.A.S.T.A

        Args:
            project_path: Path to project to analyze
            business_context: Business context information
            findings: Existing vulnerability findings

        Returns:
            Complete threat model report
        """
        # Stage 1: Define Objectives
        if business_context:
            self.pasta.stage1_define_objectives(business_context)

        # Stage 2: Define Technical Scope
        self.pasta.stage2_define_technical_scope(project_path)

        # Stage 3: Application Decomposition
        self.pasta.stage3_application_decomposition(project_path)

        # Stage 4: Threat Analysis
        self.pasta.stage4_threat_analysis()

        # Stage 5: Vulnerability Analysis (if findings provided)
        if findings:
            self.pasta.stage5_vulnerability_analysis(findings)

        # Stage 6: Attack Modeling
        attack_scenarios = self.pasta.stage6_attack_modeling()

        # Stage 7: Risk & Impact Analysis
        self.pasta.stage7_risk_impact_analysis()

        # Generate full report
        report = self.pasta.generate_full_report()
        report['attack_scenarios'] = attack_scenarios

        return report

    def add_custom_prompt(self, prompt: str):
        """Add custom threat modeling prompt"""
        self.custom_prompts.append(prompt)

    def add_internal_doc(self, doc_name: str, doc_content: str):
        """Add internal documentation for context"""
        self.internal_docs[doc_name] = doc_content
