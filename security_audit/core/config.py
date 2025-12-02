"""
Configuration system for security audit
"""
import json
from typing import Dict, Any, List
from pathlib import Path


DEFAULT_CONFIG = {
    "scan_options": {
        "max_file_size_mb": 10,
        "excluded_dirs": [
            ".git",
            "node_modules",
            "vendor",
            "venv",
            "__pycache__",
            "build",
            "dist",
            ".next",
            "target"
        ],
        "excluded_files": [
            "*.min.js",
            "*.min.css",
            "*.map",
            "package-lock.json",
            "yarn.lock"
        ],
        "included_extensions": [
            ".py", ".js", ".ts", ".jsx", ".tsx",
            ".php", ".java", ".rb", ".go", ".cs",
            ".html", ".htm", ".xml", ".json",
            ".yml", ".yaml", ".env", ".config",
            ".rs", ".kt", ".scala", ".ex", ".exs"
        ]
    },
    "scanners": {
        "web_vulnerabilities": {
            "enabled": True,
            "severity_threshold": "INFO",
            "checks": {
                "sql_injection": True,
                "xss": True,
                "command_injection": True,
                "path_traversal": True,
                "ssrf": True,
                "xxe": True,
                "csrf": True,
                "insecure_deserialization": True,
                "weak_crypto": True,
                "hardcoded_credentials": True
            }
        },
        "secrets_detector": {
            "enabled": True,
            "severity_threshold": "INFO",
            "patterns": {
                "api_keys": True,
                "passwords": True,
                "tokens": True,
                "private_keys": True,
                "connection_strings": True
            }
        },
        "dependency_scanner": {
            "enabled": True,
            "severity_threshold": "MEDIUM",
            "check_outdated": True
        },
        "config_analyzer": {
            "enabled": True,
            "severity_threshold": "INFO"
        },
        "asvs_scanner": {
            "enabled": True,
            "asvs_level": 1,
            "severity_threshold": "INFO"
        },
        "multilanguage_scanner": {
            "enabled": True,
            "severity_threshold": "INFO"
        }
    },
    "reporting": {
        "output_format": "json",
        "include_code_snippets": True,
        "snippet_context_lines": 3,
        "group_by": "severity"
    }
}


class Config:
    """Configuration manager"""

    def __init__(self, config_path: str = None):
        self.config = DEFAULT_CONFIG.copy()
        if config_path:
            self.load_from_file(config_path)

    def load_from_file(self, config_path: str):
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                self._merge_config(user_config)
        except FileNotFoundError:
            print(f"Configuration file not found: {config_path}")
        except json.JSONDecodeError as e:
            print(f"Error parsing configuration file: {e}")

    def _merge_config(self, user_config: Dict[str, Any]):
        """Merge user configuration with defaults"""
        def deep_merge(default: dict, override: dict) -> dict:
            result = default.copy()
            for key, value in override.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = deep_merge(result[key], value)
                else:
                    result[key] = value
            return result

        self.config = deep_merge(self.config, user_config)

    def get(self, key: str, default=None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        return value

    def get_scanner_config(self, scanner_name: str) -> Dict[str, Any]:
        """Get configuration for specific scanner"""
        return self.config.get("scanners", {}).get(scanner_name, {})

    def is_scanner_enabled(self, scanner_name: str) -> bool:
        """Check if scanner is enabled"""
        return self.get_scanner_config(scanner_name).get("enabled", True)

    def get_excluded_dirs(self) -> List[str]:
        """Get list of excluded directories"""
        return self.config.get("scan_options", {}).get("excluded_dirs", [])

    def get_excluded_files(self) -> List[str]:
        """Get list of excluded file patterns"""
        return self.config.get("scan_options", {}).get("excluded_files", [])

    def get_included_extensions(self) -> List[str]:
        """Get list of included file extensions"""
        return self.config.get("scan_options", {}).get("included_extensions", [])

    def get_max_file_size(self) -> int:
        """Get maximum file size in bytes"""
        max_mb = self.config.get("scan_options", {}).get("max_file_size_mb", 10)
        return max_mb * 1024 * 1024

    def save_to_file(self, config_path: str):
        """Save configuration to file"""
        with open(config_path, 'w') as f:
            json.dump(self.config, f, indent=2)

    def to_dict(self) -> Dict[str, Any]:
        """Return configuration as dictionary"""
        return self.config.copy()
