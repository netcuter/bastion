"""
Security Audit System for Web Applications
"""
__version__ = "1.0.0"
__author__ = "Security Audit Team"

from .core import AuditEngine, Config, Finding, Severity

__all__ = ['AuditEngine', 'Config', 'Finding', 'Severity']
