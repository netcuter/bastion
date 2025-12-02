"""
ASVS (Application Security Verification Standard) Framework
Implementation of OWASP ASVS 4.0 verification requirements
"""
from enum import Enum
from typing import List, Dict, Any
from dataclasses import dataclass


class ASVSLevel(Enum):
    """ASVS verification levels"""
    LEVEL_1 = 1  # Opportunistic
    LEVEL_2 = 2  # Standard
    LEVEL_3 = 3  # Advanced


class ASVSCategory(Enum):
    """ASVS verification categories"""
    V1_ARCHITECTURE = "V1"  # Architecture, Design and Threat Modeling
    V2_AUTHENTICATION = "V2"  # Authentication
    V3_SESSION = "V3"  # Session Management
    V4_ACCESS_CONTROL = "V4"  # Access Control
    V5_VALIDATION = "V5"  # Validation, Sanitization and Encoding
    V6_CRYPTOGRAPHY = "V6"  # Stored Cryptography
    V7_ERROR_HANDLING = "V7"  # Error Handling and Logging
    V8_DATA_PROTECTION = "V8"  # Data Protection
    V9_COMMUNICATION = "V9"  # Communication
    V10_MALICIOUS_CODE = "V10"  # Malicious Code
    V11_BUSINESS_LOGIC = "V11"  # Business Logic
    V12_FILES = "V12"  # Files and Resources
    V13_API = "V13"  # API and Web Service
    V14_CONFIGURATION = "V14"  # Configuration


@dataclass
class ASVSRequirement:
    """ASVS verification requirement"""
    id: str  # e.g., "2.1.1"
    category: ASVSCategory
    level: ASVSLevel
    description: str
    verification_method: str  # What to check
    cwe_mapping: List[str]


class ASVSRequirements:
    """ASVS 4.0 Requirements Database"""

    @staticmethod
    def get_all_requirements() -> List[ASVSRequirement]:
        """Get all ASVS requirements"""
        return [
            # V2: Authentication Verification Requirements
            ASVSRequirement(
                id="2.1.1",
                category=ASVSCategory.V2_AUTHENTICATION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that user set passwords are at least 12 characters in length",
                verification_method="password_policy",
                cwe_mapping=["CWE-521"]
            ),
            ASVSRequirement(
                id="2.1.7",
                category=ASVSCategory.V2_AUTHENTICATION,
                level=ASVSLevel.LEVEL_1,
                description="Verify passwords are stored in a form that is resistant to offline attacks",
                verification_method="password_hashing",
                cwe_mapping=["CWE-916", "CWE-759"]
            ),
            ASVSRequirement(
                id="2.2.1",
                category=ASVSCategory.V2_AUTHENTICATION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that anti-automation controls are effective at mitigating breached credential testing, brute force, and account lockout attacks",
                verification_method="rate_limiting",
                cwe_mapping=["CWE-307"]
            ),
            ASVSRequirement(
                id="2.5.1",
                category=ASVSCategory.V2_AUTHENTICATION,
                level=ASVSLevel.LEVEL_2,
                description="Verify that a system generated initial password or activation code SHOULD be securely randomly generated",
                verification_method="secure_random",
                cwe_mapping=["CWE-330"]
            ),

            # V3: Session Management Verification Requirements
            ASVSRequirement(
                id="3.1.1",
                category=ASVSCategory.V3_SESSION,
                level=ASVSLevel.LEVEL_1,
                description="Verify the application never reveals session tokens in URL parameters or error messages",
                verification_method="session_exposure",
                cwe_mapping=["CWE-598"]
            ),
            ASVSRequirement(
                id="3.2.1",
                category=ASVSCategory.V3_SESSION,
                level=ASVSLevel.LEVEL_1,
                description="Verify the application generates a new session token on user authentication",
                verification_method="session_fixation",
                cwe_mapping=["CWE-384"]
            ),
            ASVSRequirement(
                id="3.3.1",
                category=ASVSCategory.V3_SESSION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that logout and expiration invalidate the session token",
                verification_method="session_invalidation",
                cwe_mapping=["CWE-613"]
            ),
            ASVSRequirement(
                id="3.4.1",
                category=ASVSCategory.V3_SESSION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that cookie-based session tokens have the 'Secure' attribute set",
                verification_method="cookie_secure_flag",
                cwe_mapping=["CWE-614"]
            ),
            ASVSRequirement(
                id="3.4.2",
                category=ASVSCategory.V3_SESSION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that cookie-based session tokens have the 'HttpOnly' attribute set",
                verification_method="cookie_httponly_flag",
                cwe_mapping=["CWE-1004"]
            ),
            ASVSRequirement(
                id="3.4.3",
                category=ASVSCategory.V3_SESSION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that cookie-based session tokens utilize the 'SameSite' attribute",
                verification_method="cookie_samesite_flag",
                cwe_mapping=["CWE-16"]
            ),

            # V4: Access Control Verification Requirements
            ASVSRequirement(
                id="4.1.1",
                category=ASVSCategory.V4_ACCESS_CONTROL,
                level=ASVSLevel.LEVEL_1,
                description="Verify that the application enforces access control rules on a trusted service layer",
                verification_method="access_control_enforcement",
                cwe_mapping=["CWE-284"]
            ),
            ASVSRequirement(
                id="4.1.5",
                category=ASVSCategory.V4_ACCESS_CONTROL,
                level=ASVSLevel.LEVEL_1,
                description="Verify that access controls fail securely including when an exception occurs",
                verification_method="fail_secure",
                cwe_mapping=["CWE-285"]
            ),

            # V5: Validation, Sanitization and Encoding
            ASVSRequirement(
                id="5.1.1",
                category=ASVSCategory.V5_VALIDATION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that the application has defenses against HTTP parameter pollution attacks",
                verification_method="parameter_pollution",
                cwe_mapping=["CWE-235"]
            ),
            ASVSRequirement(
                id="5.2.1",
                category=ASVSCategory.V5_VALIDATION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that all untrusted HTML input from WYSIWYG editors or similar is properly sanitized",
                verification_method="html_sanitization",
                cwe_mapping=["CWE-116"]
            ),
            ASVSRequirement(
                id="5.3.1",
                category=ASVSCategory.V5_VALIDATION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that output encoding is relevant for the interpreter and context required",
                verification_method="output_encoding",
                cwe_mapping=["CWE-116"]
            ),
            ASVSRequirement(
                id="5.3.3",
                category=ASVSCategory.V5_VALIDATION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that context-aware output escaping or sanitization protects against XSS",
                verification_method="xss_protection",
                cwe_mapping=["CWE-79"]
            ),
            ASVSRequirement(
                id="5.3.4",
                category=ASVSCategory.V5_VALIDATION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that data selection or database queries use parameterized queries",
                verification_method="parameterized_queries",
                cwe_mapping=["CWE-89"]
            ),

            # V6: Stored Cryptography Verification Requirements
            ASVSRequirement(
                id="6.2.1",
                category=ASVSCategory.V6_CRYPTOGRAPHY,
                level=ASVSLevel.LEVEL_1,
                description="Verify that all cryptographic modules fail securely",
                verification_method="crypto_fail_secure",
                cwe_mapping=["CWE-310"]
            ),
            ASVSRequirement(
                id="6.2.2",
                category=ASVSCategory.V6_CRYPTOGRAPHY,
                level=ASVSLevel.LEVEL_2,
                description="Verify that industry proven or government approved cryptographic algorithms are used",
                verification_method="approved_crypto",
                cwe_mapping=["CWE-327"]
            ),
            ASVSRequirement(
                id="6.2.5",
                category=ASVSCategory.V6_CRYPTOGRAPHY,
                level=ASVSLevel.LEVEL_2,
                description="Verify that known insecure block modes (e.g., ECB) are not used",
                verification_method="secure_block_modes",
                cwe_mapping=["CWE-327"]
            ),

            # V7: Error Handling and Logging
            ASVSRequirement(
                id="7.1.1",
                category=ASVSCategory.V7_ERROR_HANDLING,
                level=ASVSLevel.LEVEL_1,
                description="Verify that the application does not log credentials or payment details",
                verification_method="sensitive_data_logging",
                cwe_mapping=["CWE-532"]
            ),
            ASVSRequirement(
                id="7.4.1",
                category=ASVSCategory.V7_ERROR_HANDLING,
                level=ASVSLevel.LEVEL_1,
                description="Verify that a generic message is shown when an unexpected error occurs",
                verification_method="generic_error_messages",
                cwe_mapping=["CWE-209"]
            ),

            # V8: Data Protection
            ASVSRequirement(
                id="8.1.1",
                category=ASVSCategory.V8_DATA_PROTECTION,
                level=ASVSLevel.LEVEL_2,
                description="Verify the application protects sensitive data from being cached",
                verification_method="cache_control",
                cwe_mapping=["CWE-524"]
            ),
            ASVSRequirement(
                id="8.2.1",
                category=ASVSCategory.V8_DATA_PROTECTION,
                level=ASVSLevel.LEVEL_1,
                description="Verify the application sets sufficient anti-caching headers",
                verification_method="anti_caching_headers",
                cwe_mapping=["CWE-525"]
            ),
            ASVSRequirement(
                id="8.3.4",
                category=ASVSCategory.V8_DATA_PROTECTION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that sensitive data is sent to the server in HTTP message body or headers",
                verification_method="sensitive_data_in_url",
                cwe_mapping=["CWE-319"]
            ),

            # V9: Communication
            ASVSRequirement(
                id="9.1.1",
                category=ASVSCategory.V9_COMMUNICATION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that TLS is used for all client connectivity",
                verification_method="tls_enforcement",
                cwe_mapping=["CWE-319"]
            ),
            ASVSRequirement(
                id="9.1.2",
                category=ASVSCategory.V9_COMMUNICATION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that TLS settings are in line with current best practices",
                verification_method="tls_configuration",
                cwe_mapping=["CWE-326"]
            ),
            ASVSRequirement(
                id="9.2.1",
                category=ASVSCategory.V9_COMMUNICATION,
                level=ASVSLevel.LEVEL_2,
                description="Verify that connections to and from the server use trusted TLS certificates",
                verification_method="certificate_validation",
                cwe_mapping=["CWE-295"]
            ),

            # V10: Malicious Code
            ASVSRequirement(
                id="10.2.1",
                category=ASVSCategory.V10_MALICIOUS_CODE,
                level=ASVSLevel.LEVEL_2,
                description="Verify that the application source code does not contain time bombs",
                verification_method="time_bombs",
                cwe_mapping=["CWE-511"]
            ),
            ASVSRequirement(
                id="10.3.1",
                category=ASVSCategory.V10_MALICIOUS_CODE,
                level=ASVSLevel.LEVEL_2,
                description="Verify that if the application has a client or server auto-update feature, updates should be obtained over secure channels",
                verification_method="secure_updates",
                cwe_mapping=["CWE-494"]
            ),

            # V12: Files and Resources
            ASVSRequirement(
                id="12.1.1",
                category=ASVSCategory.V12_FILES,
                level=ASVSLevel.LEVEL_1,
                description="Verify that the application will not accept large files that could fill up storage",
                verification_method="file_size_limits",
                cwe_mapping=["CWE-400"]
            ),
            ASVSRequirement(
                id="12.3.1",
                category=ASVSCategory.V12_FILES,
                level=ASVSLevel.LEVEL_1,
                description="Verify that user-submitted filename metadata is not used directly",
                verification_method="filename_validation",
                cwe_mapping=["CWE-22"]
            ),
            ASVSRequirement(
                id="12.5.1",
                category=ASVSCategory.V12_FILES,
                level=ASVSLevel.LEVEL_2,
                description="Verify that files obtained from untrusted sources are validated to be of expected type",
                verification_method="file_type_validation",
                cwe_mapping=["CWE-434"]
            ),

            # V13: API and Web Service
            ASVSRequirement(
                id="13.1.1",
                category=ASVSCategory.V13_API,
                level=ASVSLevel.LEVEL_1,
                description="Verify that all application components use the same encodings and parsers",
                verification_method="consistent_encoding",
                cwe_mapping=["CWE-116"]
            ),
            ASVSRequirement(
                id="13.2.1",
                category=ASVSCategory.V13_API,
                level=ASVSLevel.LEVEL_1,
                description="Verify that enabled RESTful HTTP methods are a valid choice",
                verification_method="http_method_validation",
                cwe_mapping=["CWE-650"]
            ),
            ASVSRequirement(
                id="13.2.3",
                category=ASVSCategory.V13_API,
                level=ASVSLevel.LEVEL_2,
                description="Verify that RESTful web services that utilize cookies are protected from CSRF",
                verification_method="api_csrf_protection",
                cwe_mapping=["CWE-352"]
            ),

            # V14: Configuration
            ASVSRequirement(
                id="14.1.1",
                category=ASVSCategory.V14_CONFIGURATION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that the application build and deployment processes are performed in a secure fashion",
                verification_method="secure_build",
                cwe_mapping=["CWE-16"]
            ),
            ASVSRequirement(
                id="14.2.1",
                category=ASVSCategory.V14_CONFIGURATION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that all components are up to date",
                verification_method="component_currency",
                cwe_mapping=["CWE-1104"]
            ),
            ASVSRequirement(
                id="14.3.3",
                category=ASVSCategory.V14_CONFIGURATION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that debug modes are disabled in production",
                verification_method="debug_mode_disabled",
                cwe_mapping=["CWE-489"]
            ),
            ASVSRequirement(
                id="14.4.1",
                category=ASVSCategory.V14_CONFIGURATION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that every HTTP response contains a Content-Type header",
                verification_method="content_type_header",
                cwe_mapping=["CWE-345"]
            ),
            ASVSRequirement(
                id="14.4.3",
                category=ASVSCategory.V14_CONFIGURATION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that a Content Security Policy is in place",
                verification_method="csp_header",
                cwe_mapping=["CWE-1021"]
            ),
            ASVSRequirement(
                id="14.4.4",
                category=ASVSCategory.V14_CONFIGURATION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that all responses contain X-Content-Type-Options: nosniff",
                verification_method="content_type_options",
                cwe_mapping=["CWE-16"]
            ),
            ASVSRequirement(
                id="14.4.5",
                category=ASVSCategory.V14_CONFIGURATION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that HTTP Strict Transport Security headers are included",
                verification_method="hsts_header",
                cwe_mapping=["CWE-523"]
            ),
            ASVSRequirement(
                id="14.4.7",
                category=ASVSCategory.V14_CONFIGURATION,
                level=ASVSLevel.LEVEL_1,
                description="Verify that a suitable Referrer-Policy header is included",
                verification_method="referrer_policy",
                cwe_mapping=["CWE-116"]
            ),
        ]

    @staticmethod
    def get_requirements_by_level(level: ASVSLevel) -> List[ASVSRequirement]:
        """Get requirements for specific ASVS level"""
        all_reqs = ASVSRequirements.get_all_requirements()
        # Include all requirements at or below the specified level
        return [req for req in all_reqs if req.level.value <= level.value]

    @staticmethod
    def get_requirements_by_category(category: ASVSCategory) -> List[ASVSRequirement]:
        """Get requirements for specific category"""
        all_reqs = ASVSRequirements.get_all_requirements()
        return [req for req in all_reqs if req.category == category]
