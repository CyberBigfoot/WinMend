"""WinMend core: task host base."""

from __future__ import annotations

from winmend.core.recommendations import RecommendationsTasks
from winmend.core.task_execution import TaskExecutionTasks
from winmend.features.activation import ActivationTasks
from winmend.features.amd import AmdTasks
from winmend.features.apps.operations import AppsTasks
from winmend.features.boot import BootTasks
from winmend.features.browser import BrowserTasks
from winmend.features.cleanup import CleanupTasks
from winmend.features.crashes import CrashesTasks
from winmend.features.debloat.operations import DebloatTasks
from winmend.features.devices import DevicesTasks
from winmend.features.explorer.operations import ExplorerTasks
from winmend.features.external_tools import ExternalToolsTasks
from winmend.features.hardware_tests import HardwareTestsTasks
from winmend.features.network import NetworkTasks
from winmend.features.office.operations import OfficeTasks
from winmend.features.performance import PerformanceTasks
from winmend.features.power import PowerTasks
from winmend.features.privacy import PrivacyTasks
from winmend.features.protection import ProtectionTasks
from winmend.features.recovery import RecoveryTasks
from winmend.features.reporting import ReportingTasks
from winmend.features.scheduled_tasks import ScheduledTasksTasks
from winmend.features.security import SecurityTasks
from winmend.features.shell import ShellTasks
from winmend.features.startup.operations import StartupTasks
from winmend.features.storage.operations import StorageTasks
from winmend.features.system_repair import SystemRepairTasks
from winmend.features.updates import UpdatesTasks


class SystemCleanerGUI(
    RecommendationsTasks,
    TaskExecutionTasks,
    ExternalToolsTasks,
    ReportingTasks,
    UpdatesTasks,
    NetworkTasks,
    ShellTasks,
    CleanupTasks,
    DevicesTasks,
    BootTasks,
    StorageTasks,
    SecurityTasks,
    SystemRepairTasks,
    PerformanceTasks,
    StartupTasks,
    BrowserTasks,
    DebloatTasks,
    AppsTasks,
    CrashesTasks,
    ProtectionTasks,
    ActivationTasks,
    RecoveryTasks,
    PowerTasks,
    HardwareTestsTasks,
    PrivacyTasks,
    ScheduledTasksTasks,
    ExplorerTasks,
    OfficeTasks,
    AmdTasks,
):
    """The task implementations -- every routine that talks to DISM, SFC, netsh,
    winreg, bcdedit and friends.

    The name is historical: this class used to be the tkinter window as well as
    the task engine. The window is gone; what is left is the proven half, and
    WMTaskHost subclasses it to supply the Qt-side plumbing. It is never
    instantiated directly.
    """

