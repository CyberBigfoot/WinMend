"""WinMend core: security."""

from __future__ import annotations

from pathlib import Path
import os
import re


class SecurityUtils:
    """Security utilities for safe operations"""

    @staticmethod
    def sanitize_path(path_str):
        """Sanitize file paths to prevent path traversal attacks"""
        try:
            # Convert to Path object and resolve
            path = Path(path_str).resolve()

            # Check if path is within allowed directories. C:\PowerShell used to
            # be one: a root-level folder every account can modify, which the
            # Autopilot export ran an elevated script from. Nothing uses it now.
            allowed_roots = [
                Path(os.environ.get('TEMP', 'C:\\Temp')),
                Path(os.environ.get('SystemRoot', 'C:\\Windows')),
                Path(os.environ.get('APPDATA', 'C:\\Users\\Default\\AppData\\Roaming'))
            ]

            for root in allowed_roots:
                try:
                    path.relative_to(root.resolve())
                    return str(path)
                except ValueError:
                    continue

            # If not in allowed directories, reject
            raise ValueError(f"Path not in allowed directories: {path}")

        except Exception as e:
            raise ValueError(f"Invalid path: {path_str}")

    @staticmethod
    def sanitize_command_args(args):
        """Sanitize command line arguments to prevent injection"""
        safe_args = []
        for arg in args:
            # Remove potentially dangerous characters
            safe_arg = re.sub(r'[;&|`$(){}[\]<>]', '', str(arg))
            # Limit length
            if len(safe_arg) > 1000:
                raise ValueError("Argument too long")
            safe_args.append(safe_arg)
        return safe_args

    @staticmethod
    def validate_registry_key(key_path):
        """Validate registry key paths"""
        allowed_patterns = [
            r'^SOFTWARE\\Microsoft\\Windows\\',
            r'^SOFTWARE\\Policies\\Microsoft\\Windows\\',
            r'^SYSTEM\\CurrentControlSet\\Control\\',
            r'^SOFTWARE\\Microsoft\\GameBar',
            r'^SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches'
        ]

        for pattern in allowed_patterns:
            if re.match(pattern, key_path, re.IGNORECASE):
                return True

        raise ValueError(f"Registry key not allowed: {key_path}")
