"""Explicit Linux environment profile used by the first runtime adapters."""

from __future__ import annotations

import hashlib
import os
import platform
import resource
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from .adapters import Capabilities
from .ir import EnvironmentObservation
from .schema import SCHEMA_VERSION, SchemaMixin


@dataclass(frozen=True)
class LinuxEnvironmentProfile(SchemaMixin):
    os_name: str = "linux"
    kernel: str = "unknown"
    architecture: str = "unknown"
    libc: str = "unknown"
    abi: str = "unknown"
    syscall_surface: str = "observed-host-kernel"
    namespaces: tuple[str, ...] = ()
    cgroup_mode: str = "unknown"
    filesystem_fixture: str = "unknown"
    clock_source: str = "unknown"
    randomness: str = "unknown"
    scheduler: str = "uncontrolled-host-scheduler"
    memory_model: str = "linux-virtual-memory;hardware-ordering-unverified"
    resource_limits: str = "unknown"
    snapshot_scope: str = "process-local-only"
    network_namespace: str = "uncontrolled-host-network"
    assumptions: tuple[str, ...] = (
        "Linux host semantics are the default environment profile",
        "hardware memory ordering is not independently controlled",
        "host scheduler and external services are not replayed exactly",
    )

    @classmethod
    def collect(cls, filesystem_fixture: str | Path | None = None) -> "LinuxEnvironmentProfile":
        libc_name, libc_version = platform.libc_ver()
        libc = " ".join(item for item in (libc_name, libc_version) if item) or "unknown"
        namespace_path = Path("/proc/self/ns")
        namespaces = tuple(sorted(item.name for item in namespace_path.iterdir())) if namespace_path.is_dir() else ()
        cgroup_mode = "v2-or-host-configured" if Path("/sys/fs/cgroup/cgroup.controllers").exists() else "unknown"
        limits = resource.getrlimit(resource.RLIMIT_NOFILE)
        return cls(
            kernel=platform.release(),
            architecture=platform.machine() or "unknown",
            libc=libc,
            abi=cls._abi(),
            namespaces=namespaces,
            cgroup_mode=cgroup_mode,
            filesystem_fixture=str(filesystem_fixture or "unknown"),
            clock_source="python-time;runtime-specific clocks may differ",
            randomness="host entropy;seed unknown",
            resource_limits=f"nofile={limits[0]}:{limits[1]}",
        )

    @staticmethod
    def _abi() -> str:
        machine = platform.machine().lower()
        if machine in {"x86_64", "amd64"}:
            return "linux-x86_64-sysv-abi"
        if machine in {"aarch64", "arm64"}:
            return "linux-aarch64-abi"
        return "unknown"

    @property
    def profile_id(self) -> str:
        payload = "|".join((self.os_name, self.kernel, self.architecture, self.libc, self.abi, self.cgroup_mode, self.snapshot_scope))
        return "linux-" + hashlib.sha256(payload.encode()).hexdigest()[:16]

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({
            "linux.host.identity",
            "linux.process.limits",
            "linux.filesystem.fixture",
            "linux.profile.observed",
        })

    def facts(self) -> dict[str, str]:
        return {
            "environment_profile": self.profile_id,
            "os": self.os_name,
            "kernel": self.kernel,
            "architecture": self.architecture,
            "libc": self.libc,
            "abi": self.abi,
            "syscall_surface": self.syscall_surface,
            "namespaces": ",".join(self.namespaces) or "unknown",
            "cgroup_mode": self.cgroup_mode,
            "filesystem_fixture": self.filesystem_fixture,
            "clock_source": self.clock_source,
            "randomness": self.randomness,
            "scheduler": self.scheduler,
            "memory_model": self.memory_model,
            "resource_limits": self.resource_limits,
            "snapshot_scope": self.snapshot_scope,
            "network_namespace": self.network_namespace,
        }

    def observation(self) -> EnvironmentObservation:
        return EnvironmentObservation(
            facts=self.facts(),
            unknown=("randomness", "scheduler", "memory_ordering", "network_namespace", "external_services"),
            redacted_keys=("environment_values", "credentials", "host identifiers not needed for replay"),
            profile_id=self.profile_id,
            capabilities=self.capabilities,
        )

    @classmethod
    def from_observed(cls, facts: Mapping[str, str], *, assumptions: tuple[str, ...] = ()) -> "LinuxEnvironmentProfile":
        """Build a guest profile from adapter-observed facts without host probing."""
        return cls(
            os_name=facts.get("os", "linux"),
            kernel=facts.get("kernel", "unknown"),
            architecture=facts.get("architecture", "unknown"),
            libc=facts.get("libc", "unknown"),
            abi=facts.get("abi", "unknown"),
            syscall_surface=facts.get("syscall_surface", "guest-kernel"),
            namespaces=tuple(filter(None, facts.get("namespaces", "").split(","))),
            cgroup_mode=facts.get("cgroup_mode", "unknown"),
            filesystem_fixture=facts.get("filesystem_fixture", "guest-rootfs"),
            clock_source=facts.get("clock_source", "unknown"),
            randomness=facts.get("randomness", "unknown"),
            scheduler=facts.get("scheduler", "unknown"),
            memory_model=facts.get("memory_model", "linux-virtual-memory;hardware-ordering-unverified"),
            resource_limits=facts.get("resource_limits", "unknown"),
            snapshot_scope=facts.get("snapshot_scope", "unknown"),
            network_namespace=facts.get("network_namespace", "unknown"),
            assumptions=assumptions or cls().assumptions,
        )


class LinuxEnvironmentAdapter:
    """EnvironmentAdapter implementation for a host-local Linux profile."""

    def __init__(self, filesystem_fixture: str | Path | None = None) -> None:
        self.filesystem_fixture = str(filesystem_fixture or "unknown")
        self._profile: LinuxEnvironmentProfile | None = None

    @property
    def capabilities(self) -> Capabilities:
        return Capabilities(capture_state=False, snapshot=False)

    @property
    def profile(self) -> LinuxEnvironmentProfile:
        if self._profile is None:
            self._profile = LinuxEnvironmentProfile.collect(self.filesystem_fixture)
        return self._profile

    def describe(self) -> Mapping[str, str]:
        return self.profile.facts()

    def observe(self) -> EnvironmentObservation:
        return self.profile.observation()

    def satisfies(self, requirements: Mapping[str, str]) -> bool:
        facts = self.profile.facts()
        return all(facts.get(key) == value for key, value in requirements.items())
