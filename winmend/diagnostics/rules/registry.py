"""WinMend diagnostics: rules: registry."""

from __future__ import annotations




# Each rule takes a Context and returns a Hypothesis, a list of them, or None.
RULES = []


def rule(func):
    RULES.append(func)
    return func
