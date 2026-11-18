"""Diagnostic rules, registered in their original evaluation order."""

from winmend.diagnostics.rules import hardware
from winmend.diagnostics.rules import history
from winmend.diagnostics.rules import network
from winmend.diagnostics.rules import system
from winmend.diagnostics.rules import security
from winmend.diagnostics.rules import storage
from winmend.diagnostics.rules import upkeep
from winmend.diagnostics.rules import context
from winmend.diagnostics.rules import boot
from winmend.diagnostics.rules import storage_upkeep
from winmend.diagnostics.rules import network_stack
from winmend.diagnostics.rules import updates
from winmend.diagnostics.rules import desktop
from winmend.diagnostics.rules import components
from .registry import RULES
