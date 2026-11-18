"""Minimize identifiers in shareable reports, without modifying local evidence."""
import re

SECRET_KEYS = frozenset(("password", "token", "secret", "authorization", "ssid", "serial", "mac", "username", "computername"))


def redact(value, identifiers=None):
    if identifiers is None:
        identifiers = set()
        def collect(item):
            if isinstance(item, dict):
                for key, child in item.items():
                    if str(key).lower() in SECRET_KEYS and isinstance(child, str) and len(child) > 2:
                        identifiers.add(child)
                    collect(child)
            elif isinstance(item, (list, tuple)):
                for child in item:
                    collect(child)
        collect(value)
    if isinstance(value, dict):
        return {k: "[redacted]" if str(k).lower() in SECRET_KEYS else redact(v, identifiers) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, identifiers) for v in value]
    if not isinstance(value, str):
        return value
    text = re.sub(r"(?i)\b[A-Z]:\\Users\\[^\\\s<>]+", r"C:\\Users\\[redacted]", value)
    text = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[email redacted]", text)
    text = re.sub(r"(?i)(https?://)[^/@\s]+:[^/@\s]+@", r"\1[credentials redacted]@", text)
    text = re.sub(r"(?i)((?:token|password|secret|api_key)=)[^&\s]+", r"\1[redacted]", text)
    text = re.sub(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b", "[private address]", text)
    for identifier in sorted(identifiers, key=len, reverse=True):
        text = re.sub(re.escape(identifier), "[redacted]", text, flags=re.IGNORECASE)
    return text
