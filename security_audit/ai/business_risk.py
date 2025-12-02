"""
Business Context Risk Assessment
Contextual risk evaluation based on business impact

Features:
- Business-specific risk modeling
- Industry compliance mapping (GDPR, HIPAA, PCI-DSS, etc.)
- Asset criticality assessment
- Financial impact estimation
- Regulatory impact analysis
- Reputation risk analysis
"""
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field
from enum import Enum


class IndustryType(Enum):
    """Industry types"""
    FINANCE = "finance"
    HEALTHCARE = "healthcare"
    ECOMMERCE = "ecommerce"
    GOVERNMENT = "government"
    TECHNOLOGY = "technology"
    EDUCATION = "education"
    MEDIA = "media"
    MANUFACTURING = "manufacturing"
    RETAIL = "retail"
    TELECOMMUNICATIONS = "telecommunications"


class ComplianceFramework(Enum):
    """Compliance frameworks"""
    GDPR = "gdpr"  # General Data Protection Regulation
    HIPAA = "hipaa"  # Health Insurance Portability and Accountability Act
    PCI_DSS = "pci_dss"  # Payment Card Industry Data Security Standard
    SOC2 = "soc2"  # Service Organization Control 2
    ISO27001 = "iso27001"  # Information Security Management
    NIST = "nist"  # National Institute of Standards and Technology
    CCPA = "ccpa"  # California Consumer Privacy Act
    FERPA = "ferpa"  # Family Educational Rights and Privacy Act
    GLBA = "glba"  # Gramm-Leach-Bliley Act


class AssetCriticality(Enum):
    """Asset criticality levels"""
    CRITICAL = "critical"  # Business-critical, downtime unacceptable
    HIGH = "high"  # Important for business operations
    MEDIUM = "medium"  # Supports business operations
    LOW = "low"  # Non-essential


@dataclass
class BusinessAsset:
    """Business asset definition"""
    asset_id: str = ""
    name: str = ""
    description: str = ""
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    data_types: List[str] = field(default_factory=list)  # PII, payment cards, health records, etc.
    user_base_size: int = 0
    revenue_impact: float = 0.0  # USD
    compliance_requirements: List[ComplianceFramework] = field(default_factory=list)
    geographic_scope: List[str] = field(default_factory=list)  # Countries/regions


@dataclass
class RiskScore:
    """Comprehensive risk score"""
    technical_severity: str = ""  # CRITICAL, HIGH, MEDIUM, LOW
    business_impact: str = ""  # CRITICAL, HIGH, MEDIUM, LOW
    likelihood: str = ""  # CRITICAL, HIGH, MEDIUM, LOW
    overall_risk: float = 0.0  # 0-10 scale
    financial_impact_min: float = 0.0  # USD
    financial_impact_max: float = 0.0  # USD
    compliance_violations: List[str] = field(default_factory=list)
    reputation_impact: str = ""


@dataclass
class BusinessRiskAssessment:
    """Complete business risk assessment"""
    vulnerability_id: str = ""
    vulnerability_type: str = ""
    affected_assets: List[str] = field(default_factory=list)
    risk_score: Optional[RiskScore] = None
    business_context: str = ""
    exploitation_scenario: str = ""
    business_impact_description: str = ""
    regulatory_impact: str = ""
    mitigation_priority: str = ""
    recommended_timeline: str = ""


class BusinessRiskAnalyzer:
    """
    Business context risk analyzer

    Evaluates vulnerabilities in business context
    Provides business-relevant risk scores
    """

    def __init__(self, industry: IndustryType, compliance_frameworks: List[ComplianceFramework]):
        self.industry = industry
        self.compliance_frameworks = compliance_frameworks
        self.business_assets: Dict[str, BusinessAsset] = {}
        self.assessments: List[BusinessRiskAssessment] = []

        # Industry-specific risk multipliers
        self.industry_risk_multipliers = {
            IndustryType.FINANCE: 1.5,
            IndustryType.HEALTHCARE: 1.4,
            IndustryType.GOVERNMENT: 1.3,
            IndustryType.ECOMMERCE: 1.2,
            IndustryType.TECHNOLOGY: 1.0,
            IndustryType.EDUCATION: 0.9,
            IndustryType.MEDIA: 0.8,
            IndustryType.MANUFACTURING: 0.9,
            IndustryType.RETAIL: 1.1,
            IndustryType.TELECOMMUNICATIONS: 1.2
        }

        # Compliance framework penalties (for violations)
        self.compliance_penalties = {
            ComplianceFramework.GDPR: 20000000,  # Up to €20M
            ComplianceFramework.HIPAA: 1500000,  # Up to $1.5M
            ComplianceFramework.PCI_DSS: 500000,  # Up to $500K
            ComplianceFramework.CCPA: 7500,  # $7,500 per violation
            ComplianceFramework.SOC2: 100000,  # Estimated
            ComplianceFramework.ISO27001: 50000,  # Estimated
            ComplianceFramework.NIST: 100000,  # Estimated
        }

    def register_business_asset(self, asset: BusinessAsset):
        """Register a business asset"""
        self.business_assets[asset.asset_id] = asset

    def assess_vulnerability(self, vulnerability: Dict[str, Any],
                           affected_asset_ids: List[str]) -> BusinessRiskAssessment:
        """
        Assess vulnerability in business context

        Args:
            vulnerability: Technical vulnerability finding
            affected_asset_ids: List of affected business asset IDs

        Returns:
            Business risk assessment
        """
        assessment = BusinessRiskAssessment(
            vulnerability_id=vulnerability.get('id', ''),
            vulnerability_type=vulnerability.get('type', ''),
            affected_assets=affected_asset_ids
        )

        # Get affected assets
        affected_assets = [self.business_assets[aid] for aid in affected_asset_ids
                          if aid in self.business_assets]

        # Calculate risk score
        risk_score = self._calculate_risk_score(vulnerability, affected_assets)
        assessment.risk_score = risk_score

        # Generate business context
        assessment.business_context = self._generate_business_context(affected_assets)

        # Generate exploitation scenario
        assessment.exploitation_scenario = self._generate_exploitation_scenario(
            vulnerability, affected_assets
        )

        # Assess business impact
        assessment.business_impact_description = self._assess_business_impact(
            vulnerability, affected_assets, risk_score
        )

        # Assess regulatory impact
        assessment.regulatory_impact = self._assess_regulatory_impact(
            vulnerability, affected_assets, risk_score
        )

        # Determine mitigation priority
        assessment.mitigation_priority = self._determine_priority(risk_score)

        # Recommend timeline
        assessment.recommended_timeline = self._recommend_timeline(risk_score)

        self.assessments.append(assessment)
        return assessment

    def _calculate_risk_score(self, vulnerability: Dict[str, Any],
                             affected_assets: List[BusinessAsset]) -> RiskScore:
        """Calculate comprehensive risk score"""
        # Technical severity
        technical_severity = vulnerability.get('severity', 'MEDIUM')

        # Determine business impact based on asset criticality
        business_impact = self._determine_business_impact(affected_assets)

        # Determine likelihood based on exploitability
        likelihood = self._determine_likelihood(vulnerability)

        # Calculate overall risk (0-10 scale)
        severity_scores = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 5, 'LOW': 2, 'INFO': 1}
        impact_scores = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 5, 'LOW': 2}
        likelihood_scores = {'CRITICAL': 1.0, 'HIGH': 0.7, 'MEDIUM': 0.5, 'LOW': 0.3}

        technical_score = severity_scores.get(technical_severity, 5)
        impact_score = impact_scores.get(business_impact, 5)
        likelihood_factor = likelihood_scores.get(likelihood, 0.5)

        # Apply industry multiplier
        industry_multiplier = self.industry_risk_multipliers.get(self.industry, 1.0)

        overall_risk = ((technical_score + impact_score) / 2) * likelihood_factor * industry_multiplier
        overall_risk = min(10.0, overall_risk)  # Cap at 10

        # Estimate financial impact
        financial_impact = self._estimate_financial_impact(
            vulnerability, affected_assets, overall_risk
        )

        # Check compliance violations
        compliance_violations = self._check_compliance_violations(vulnerability, affected_assets)

        # Assess reputation impact
        reputation_impact = self._assess_reputation_impact(affected_assets, overall_risk)

        return RiskScore(
            technical_severity=technical_severity,
            business_impact=business_impact,
            likelihood=likelihood,
            overall_risk=overall_risk,
            financial_impact_min=financial_impact[0],
            financial_impact_max=financial_impact[1],
            compliance_violations=compliance_violations,
            reputation_impact=reputation_impact
        )

    def _determine_business_impact(self, affected_assets: List[BusinessAsset]) -> str:
        """Determine business impact level"""
        if not affected_assets:
            return "LOW"

        # Get highest criticality
        criticality_scores = {
            AssetCriticality.CRITICAL: 4,
            AssetCriticality.HIGH: 3,
            AssetCriticality.MEDIUM: 2,
            AssetCriticality.LOW: 1
        }

        max_criticality = max(
            (criticality_scores.get(asset.criticality, 1) for asset in affected_assets),
            default=1
        )

        if max_criticality >= 4:
            return "CRITICAL"
        elif max_criticality >= 3:
            return "HIGH"
        elif max_criticality >= 2:
            return "MEDIUM"
        else:
            return "LOW"

    def _determine_likelihood(self, vulnerability: Dict[str, Any]) -> str:
        """Determine exploitation likelihood"""
        vuln_type = vulnerability.get('type', '').lower()

        # High likelihood vulnerabilities
        high_likelihood = [
            'sql injection', 'xss', 'authentication bypass',
            'hardcoded credentials', 'information disclosure'
        ]

        # Medium likelihood
        medium_likelihood = [
            'command injection', 'path traversal', 'ssrf',
            'insecure deserialization', 'xxe'
        ]

        # Check if vulnerability type matches high/medium likelihood
        for high_vuln in high_likelihood:
            if high_vuln in vuln_type:
                return "HIGH"

        for medium_vuln in medium_likelihood:
            if medium_vuln in vuln_type:
                return "MEDIUM"

        return "LOW"

    def _estimate_financial_impact(self, vulnerability: Dict[str, Any],
                                   affected_assets: List[BusinessAsset],
                                   overall_risk: float) -> tuple:
        """
        Estimate financial impact range

        Returns (min_impact, max_impact) in USD
        """
        if not affected_assets:
            return (0.0, 10000.0)

        # Base impact from asset revenue impact
        base_impact = sum(asset.revenue_impact for asset in affected_assets)

        # Data breach costs (average per record)
        data_breach_costs = {
            'PII': 150,  # $150 per PII record
            'payment_cards': 200,  # $200 per card
            'health_records': 429,  # $429 per health record (HIPAA)
            'financial': 250,  # $250 per financial record
            'credentials': 100  # $100 per credential
        }

        # Estimate number of potentially affected records
        total_users = sum(asset.user_base_size for asset in affected_assets)
        exposure_rate = min(overall_risk / 10.0, 1.0)  # 0-100% based on risk

        # Calculate data breach costs
        breach_cost = 0.0
        for asset in affected_assets:
            for data_type in asset.data_types:
                cost_per_record = data_breach_costs.get(data_type, 100)
                exposed_records = asset.user_base_size * exposure_rate * 0.5  # Assume 50% exposure
                breach_cost += exposed_records * cost_per_record

        # Add compliance penalties
        penalty_cost = 0.0
        for framework in self.compliance_frameworks:
            if any(framework in asset.compliance_requirements for asset in affected_assets):
                penalty_cost += self.compliance_penalties.get(framework, 0) * 0.1  # 10% of max penalty

        # Calculate range
        min_impact = base_impact * 0.1 + breach_cost * 0.1 + penalty_cost * 0.1
        max_impact = base_impact + breach_cost + penalty_cost

        return (min_impact, max_impact)

    def _check_compliance_violations(self, vulnerability: Dict[str, Any],
                                    affected_assets: List[BusinessAsset]) -> List[str]:
        """Check which compliance frameworks are violated"""
        violations = []

        vuln_type = vulnerability.get('type', '').lower()

        # Map vulnerability types to compliance violations
        compliance_mappings = {
            ComplianceFramework.GDPR: [
                'data breach', 'information disclosure', 'weak encryption',
                'insecure storage', 'unauthorized access'
            ],
            ComplianceFramework.HIPAA: [
                'health information', 'phi', 'medical records',
                'weak encryption', 'insecure storage'
            ],
            ComplianceFramework.PCI_DSS: [
                'payment', 'credit card', 'cardholder data',
                'weak encryption', 'sql injection', 'xss'
            ],
            ComplianceFramework.SOC2: [
                'unauthorized access', 'weak authentication',
                'insufficient logging', 'weak encryption'
            ]
        }

        for framework in self.compliance_frameworks:
            # Check if framework applies to affected assets
            if any(framework in asset.compliance_requirements for asset in affected_assets):
                # Check if vulnerability violates framework
                violation_keywords = compliance_mappings.get(framework, [])
                if any(keyword in vuln_type for keyword in violation_keywords):
                    violations.append(framework.value.upper())

        return violations

    def _assess_reputation_impact(self, affected_assets: List[BusinessAsset],
                                 overall_risk: float) -> str:
        """Assess reputation impact"""
        if overall_risk >= 8.0:
            return "SEVERE - Major brand damage, customer loss, negative press"
        elif overall_risk >= 6.0:
            return "HIGH - Significant reputation damage, customer concerns"
        elif overall_risk >= 4.0:
            return "MODERATE - Some reputation impact, manageable"
        else:
            return "LOW - Minimal reputation impact"

    def _generate_business_context(self, affected_assets: List[BusinessAsset]) -> str:
        """Generate business context description"""
        if not affected_assets:
            return "No business assets directly affected"

        context_parts = []

        for asset in affected_assets:
            context_parts.append(
                f"Asset '{asset.name}' ({asset.criticality.value} criticality) "
                f"serving {asset.user_base_size:,} users"
            )

            if asset.data_types:
                context_parts.append(f"  - Handles: {', '.join(asset.data_types)}")

            if asset.compliance_requirements:
                frameworks = [f.value.upper() for f in asset.compliance_requirements]
                context_parts.append(f"  - Compliance: {', '.join(frameworks)}")

        return "\n".join(context_parts)

    def _generate_exploitation_scenario(self, vulnerability: Dict[str, Any],
                                       affected_assets: List[BusinessAsset]) -> str:
        """Generate business-relevant exploitation scenario"""
        vuln_type = vulnerability.get('type', 'Unknown')

        scenario_templates = {
            'sql injection': "Attacker extracts {data_types} from database, affecting {user_count:,} users. Data sold on dark web.",
            'xss': "Attacker steals session tokens of {user_count:,} users, gains unauthorized access to accounts.",
            'authentication bypass': "Attacker gains administrative access, compromises entire {asset_name} system.",
            'command injection': "Attacker executes arbitrary commands, potentially taking over server hosting {asset_name}.",
            'information disclosure': "Sensitive {data_types} exposed to unauthorized parties, affecting {user_count:,} users.",
        }

        # Get template
        template = None
        for key, tmpl in scenario_templates.items():
            if key in vuln_type.lower():
                template = tmpl
                break

        if template and affected_assets:
            asset = affected_assets[0]
            data_types = ', '.join(asset.data_types) if asset.data_types else 'sensitive data'
            scenario = template.format(
                asset_name=asset.name,
                data_types=data_types,
                user_count=asset.user_base_size
            )
        else:
            scenario = f"Exploitation of {vuln_type} could compromise affected systems and data."

        return scenario

    def _assess_business_impact(self, vulnerability: Dict[str, Any],
                               affected_assets: List[BusinessAsset],
                               risk_score: RiskScore) -> str:
        """Assess detailed business impact"""
        impact_parts = []

        # Financial impact
        if risk_score.financial_impact_max > 0:
            impact_parts.append(
                f"**Financial Impact:** ${risk_score.financial_impact_min:,.0f} - "
                f"${risk_score.financial_impact_max:,.0f}"
            )

        # Operational impact
        if any(asset.criticality == AssetCriticality.CRITICAL for asset in affected_assets):
            impact_parts.append(
                "**Operational Impact:** Service disruption likely, business-critical systems affected"
            )

        # Customer impact
        total_users = sum(asset.user_base_size for asset in affected_assets)
        if total_users > 0:
            impact_parts.append(
                f"**Customer Impact:** Up to {total_users:,} users potentially affected"
            )

        # Compliance impact
        if risk_score.compliance_violations:
            impact_parts.append(
                f"**Compliance Impact:** Violations of {', '.join(risk_score.compliance_violations)}"
            )

        # Reputation impact
        impact_parts.append(f"**Reputation Impact:** {risk_score.reputation_impact}")

        return "\n".join(impact_parts)

    def _assess_regulatory_impact(self, vulnerability: Dict[str, Any],
                                 affected_assets: List[BusinessAsset],
                                 risk_score: RiskScore) -> str:
        """Assess regulatory and compliance impact"""
        if not risk_score.compliance_violations:
            return "No direct compliance violations identified"

        impact_parts = [
            "**Compliance Violations Identified:**",
            ""
        ]

        for framework_name in risk_score.compliance_violations:
            framework = ComplianceFramework[framework_name]
            penalty = self.compliance_penalties.get(framework, 0)

            impact_parts.append(f"- **{framework_name}**")
            impact_parts.append(f"  - Maximum penalty: ${penalty:,}")
            impact_parts.append(f"  - Requires breach notification: Yes")
            impact_parts.append(f"  - Must report to regulator: Yes")
            impact_parts.append("")

        return "\n".join(impact_parts)

    def _determine_priority(self, risk_score: RiskScore) -> str:
        """Determine mitigation priority"""
        if risk_score.overall_risk >= 8.0:
            return "P0 - CRITICAL - Drop everything, fix immediately"
        elif risk_score.overall_risk >= 6.0:
            return "P1 - HIGH - Fix within 24-48 hours"
        elif risk_score.overall_risk >= 4.0:
            return "P2 - MEDIUM - Fix within 1-2 weeks"
        else:
            return "P3 - LOW - Fix in next sprint/release"

    def _recommend_timeline(self, risk_score: RiskScore) -> str:
        """Recommend remediation timeline"""
        if risk_score.overall_risk >= 8.0:
            return "IMMEDIATE - Within 24 hours"
        elif risk_score.overall_risk >= 6.0:
            return "URGENT - Within 3-5 business days"
        elif risk_score.overall_risk >= 4.0:
            return "STANDARD - Within 2-4 weeks"
        else:
            return "PLANNED - Next release cycle"

    def generate_executive_summary(self) -> Dict[str, Any]:
        """Generate executive summary for business stakeholders"""
        total_assessments = len(self.assessments)

        critical = sum(1 for a in self.assessments if a.risk_score.overall_risk >= 8.0)
        high = sum(1 for a in self.assessments if 6.0 <= a.risk_score.overall_risk < 8.0)
        medium = sum(1 for a in self.assessments if 4.0 <= a.risk_score.overall_risk < 6.0)
        low = sum(1 for a in self.assessments if a.risk_score.overall_risk < 4.0)

        total_financial_impact_min = sum(
            a.risk_score.financial_impact_min for a in self.assessments
        )
        total_financial_impact_max = sum(
            a.risk_score.financial_impact_max for a in self.assessments
        )

        compliance_violations = set()
        for assessment in self.assessments:
            compliance_violations.update(assessment.risk_score.compliance_violations)

        return {
            'executive_summary': {
                'total_risks_identified': total_assessments,
                'risk_distribution': {
                    'critical': critical,
                    'high': high,
                    'medium': medium,
                    'low': low
                },
                'financial_exposure': {
                    'minimum': f"${total_financial_impact_min:,.0f}",
                    'maximum': f"${total_financial_impact_max:,.0f}"
                },
                'compliance_frameworks_at_risk': list(compliance_violations),
                'industry': self.industry.value,
                'immediate_actions_required': critical + high
            },
            'top_risks': [
                {
                    'vulnerability_id': a.vulnerability_id,
                    'type': a.vulnerability_type,
                    'risk_score': a.risk_score.overall_risk,
                    'priority': a.mitigation_priority,
                    'timeline': a.recommended_timeline
                }
                for a in sorted(self.assessments, key=lambda x: x.risk_score.overall_risk, reverse=True)[:10]
            ]
        }
