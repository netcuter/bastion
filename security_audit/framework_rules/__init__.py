"""
Framework-Specific Security Rules
Context-aware detection for popular web frameworks
"""
from typing import List, Dict, Any

from .django_rules import DjangoSecurityRules
from .express_rules import ExpressSecurityRules
from .react_rules import ReactSecurityRules
from .spring_rules import SpringSecurityRules
from .laravel_rules import LaravelSecurityRules


__all__ = [
    'DjangoSecurityRules',
    'ExpressSecurityRules',
    'ReactSecurityRules',
    'SpringSecurityRules',
    'LaravelSecurityRules',
    'get_framework_rules',
]


def get_framework_rules(framework: str):
    """
    Get security rules for a specific framework

    Args:
        framework: Framework name (django, express, react, spring, laravel)

    Returns:
        Framework-specific security rules instance
    """
    framework_map = {
        'django': DjangoSecurityRules(),
        'express': ExpressSecurityRules(),
        'react': ReactSecurityRules(),
        'spring': SpringSecurityRules(),
        'laravel': LaravelSecurityRules(),
    }

    return framework_map.get(framework.lower())


def detect_framework(code: str, file_type: str) -> List[str]:
    """
    Auto-detect frameworks from code

    Args:
        code: Source code
        file_type: File extension

    Returns:
        List of detected framework names
    """
    frameworks = []

    # Django detection
    if file_type == 'py':
        if any(pattern in code for pattern in ['from django', 'import django', 'django.', 'models.Model']):
            frameworks.append('django')

    # Express detection
    if file_type in ['js', 'ts']:
        if any(pattern in code for pattern in ['express()', 'require(\'express\')', 'from \'express\'']):
            frameworks.append('express')

    # React detection
    if file_type in ['js', 'jsx', 'ts', 'tsx']:
        if any(pattern in code for pattern in ['from \'react\'', 'import React', 'React.Component', 'useState']):
            frameworks.append('react')

    # Spring detection
    if file_type == 'java':
        if any(pattern in code for pattern in ['@SpringBootApplication', '@RestController', 'import org.springframework']):
            frameworks.append('spring')

    # Laravel detection
    if file_type == 'php':
        if any(pattern in code for pattern in ['use Illuminate\\', 'namespace App\\', 'Route::']):
            frameworks.append('laravel')

    return frameworks
