"""Optional runtime and environment extensions for RSVE core."""

from .linux import LinuxEnvironmentAdapter, LinuxEnvironmentProfile
from .evm import EvmReplayReport, EvmReplayRun, EvmTargetAdapter
from .node import NodeTargetAdapter, ReplayReport, ReplayRun
from .qemu import QemuLinuxSubstrate, QemuSnapshot
from .contract import (
    EvmAdapterContract,
    EvmCapabilities,
    EvmExecutionContext,
    JvmAdapterContract,
    JvmCapabilities,
    NativeAdapterContract,
    NativeCapabilities,
    NativeTargetIdentity,
)

__all__ = [
    "EvmAdapterContract", "EvmCapabilities", "EvmExecutionContext",
    "EvmReplayReport", "EvmReplayRun", "EvmTargetAdapter",
    "JvmAdapterContract", "JvmCapabilities", "LinuxEnvironmentAdapter",
    "LinuxEnvironmentProfile", "NativeAdapterContract", "NativeCapabilities",
    "NativeTargetIdentity", "NodeTargetAdapter", "QemuLinuxSubstrate",
    "QemuSnapshot", "ReplayReport", "ReplayRun",
]
