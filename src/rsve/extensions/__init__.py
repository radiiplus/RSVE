"""Optional runtime and environment extensions for RSVE core."""

from .environment import LinuxEnvironmentAdapter, LinuxEnvironmentProfile
from .evm_adapter import EvmReplayReport, EvmReplayRun, EvmTargetAdapter
from .node_adapter import NodeTargetAdapter, ReplayReport, ReplayRun
from .qemu_adapter import QemuLinuxSubstrate, QemuSnapshot
from .runtime_contracts import (
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
