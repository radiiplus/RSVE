"""Portable QEMU/Linux substrate using an official Ubuntu Server cloud image."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .adapters import CapabilityReport, Capabilities
from .environment import LinuxEnvironmentProfile
from .ir import EnvironmentObservation
from .profile import ExecutionProfile, LayerPin


DEFAULT_IMAGE = Path("/home/codespace/.cache/rsve/qemu/ubuntu-26.04/ubuntu-26.04-server-cloudimg-amd64.img")
DEFAULT_IMAGE_SHA256 = "7b90593f5532b49b7e3fe3d2743f0d1f0d822e5b07cebcd8e00c0df8069ecab9"


@dataclass(frozen=True)
class QemuSnapshot:
    snapshot_id: str
    base_image: str
    image_sha256: str
    scope: str = "qcow2-overlay-recreated"


class QemuLinuxSubstrate:
    """Boot and observe an isolated Ubuntu Server guest through serial evidence.

    The adapter deliberately uses TCG rather than KVM so the guest execution
    boundary is portable across Linux hosts. It is a substrate adapter, not a
    target-entry adapter and does not expose guest behavior as proof by itself.
    """

    def __init__(
        self,
        *,
        image: str | Path = DEFAULT_IMAGE,
        image_sha256: str = DEFAULT_IMAGE_SHA256,
        qemu_command: str = "qemu-system-x86_64",
        qemu_img_command: str = "qemu-img",
        memory_mb: int = 1024,
        boot_timeout_s: float = 120.0,
    ) -> None:
        self.image = Path(image)
        self.image_sha256 = image_sha256
        self.qemu_command = qemu_command
        self.qemu_img_command = qemu_img_command
        self.memory_mb = memory_mb
        self.boot_timeout_s = boot_timeout_s
        self._workspace: tempfile.TemporaryDirectory[str] | None = None
        self._process: subprocess.Popen[Any] | None = None
        self._overlay: Path | None = None
        self._serial_log: Path | None = None
        self._profile: LinuxEnvironmentProfile | None = None
        self._verified_hash: str | None = None

    @property
    def capabilities(self) -> Capabilities:
        return Capabilities(replay=False, capture_state=True, capture_traces=True, snapshot=True)

    def capability_report(self) -> CapabilityReport:
        return CapabilityReport(
            supported_entry_types=frozenset({"guest_machine"}),
            supported_event_hooks=frozenset({"guest.serial", "guest.machine"}),
            state_capture=True,
            snapshot_reset=True,
            deterministic_replay=False,
            limitations=(
                "QEMU TCG emulates the selected guest machine; it does not prove all host hardware behavior",
                "the minimal substrate has no SSH, cloud-init, or guest-agent command channel",
                "guest wall clock, entropy, scheduler interleavings, and external network services are not exact replay state",
                "serial output is boot evidence, not a complete guest trace",
            ),
            side_effects=("local QEMU process, temporary qcow2 overlay, and serial log",),
        )

    def prepare(self) -> None:
        if self._process and self._process.poll() is None:
            return
        self._check_tools()
        if not self.image.is_file():
            raise FileNotFoundError(f"Ubuntu Server cloud image not found: {self.image}")
        self._verified_hash = self._sha256(self.image)
        if self.image_sha256 and self._verified_hash != self.image_sha256:
            raise ValueError("Ubuntu cloud image SHA256 does not match the pinned value")
        self._workspace = tempfile.TemporaryDirectory(prefix="rsve-qemu-")
        root = Path(self._workspace.name)
        self._overlay = root / "guest-overlay.qcow2"
        self._serial_log = root / "serial.log"
        subprocess.run([self.qemu_img_command, "create", "-f", "qcow2", "-F", "qcow2", "-b", str(self.image), str(self._overlay)], check=True, capture_output=True)
        self._process = subprocess.Popen(
            [
                self.qemu_command,
                "-machine", "q35,accel=tcg",
                "-cpu", "max",
                "-m", str(self.memory_mb),
                "-smp", "1",
                "-display", "none",
                "-monitor", "none",
                "-serial", f"file:{self._serial_log}",
                "-drive", f"file={self._overlay},if=virtio,format=qcow2",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + self.boot_timeout_s
        while time.monotonic() < deadline:
            try:
                if self._process.poll() is None and self._serial_log.exists() and self._serial_log.stat().st_size:
                    self._profile = None
                    return
            except OSError:
                time.sleep(1.0)
        serial = self._serial_log.read_text(encoding="utf-8", errors="replace")[-2000:] if self._serial_log and self._serial_log.exists() else ""
        self.teardown()
        raise TimeoutError(f"Ubuntu guest did not produce serial boot evidence; serial tail: {serial}")

    def teardown(self) -> None:
        process = self._process
        self._process = None
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        if self._workspace is not None:
            self._workspace.cleanup()
            self._workspace = None
        self._overlay = None
        self._serial_log = None
        self._profile = None

    def snapshot(self) -> QemuSnapshot:
        self.prepare()
        return QemuSnapshot(
            snapshot_id="qemu-" + (self._verified_hash or "unknown")[:16],
            base_image=str(self.image),
            image_sha256=self._verified_hash or "unknown",
        )

    def reset(self, snapshot: QemuSnapshot | Mapping[str, Any]) -> None:
        image_sha256 = (
            str(snapshot.get("image_sha256", ""))
            if isinstance(snapshot, Mapping)
            else snapshot.image_sha256
        )
        allowed_hashes = {"", self._verified_hash, self.image_sha256}
        if image_sha256 not in allowed_hashes:
            raise ValueError("snapshot does not refer to the pinned Ubuntu image")
        self.teardown()
        self.prepare()

    def execute(self, command: str) -> str:
        raise RuntimeError(
            "QEMU substrate has no guest command channel; use a target adapter or an explicit guest-agent adapter"
        )

    def serial_output(self, *, max_bytes: int = 64 * 1024) -> str:
        """Return bounded boot-console evidence from the current guest process."""
        if self._serial_log is None or not self._serial_log.exists():
            return ""
        with self._serial_log.open("rb") as handle:
            handle.seek(0, 2)
            handle.seek(max(0, handle.tell() - max_bytes))
            return handle.read(max_bytes).decode("utf-8", errors="replace")

    def identity(self) -> Mapping[str, str]:
        observation = self.environment_observation()
        return {
            "target_id": "qemu-ubuntu-26",
            "runtime": "linux-guest",
            "runtime_version": observation.facts.get("distribution", "Ubuntu Server 26.04 LTS"),
            "platform": "qemu-tcg",
            "platform_version": self._qemu_version(),
            "build_hash": self._verified_hash or self._sha256(self.image),
            "adapter": "rsve.qemu-linux",
            "adapter_version": "1",
        }

    def execution_profile(self) -> ExecutionProfile:
        return ExecutionProfile.from_target(
            self.identity(),
            self.environment_observation(),
            extra_pins=(
                LayerPin("os-image", "ubuntu-server-26.04-amd64", "26.04", self._verified_hash or self._sha256(self.image), "qemu.image"),
                LayerPin("emulator", "qemu-system-x86_64", self._qemu_version(), source="qemu.version"),
            ),
        )

    def environment_observation(self) -> EnvironmentObservation:
        self.prepare()
        facts = {
            "substrate": "qemu-tcg",
            "qemu_machine": "q35",
            "distribution": "Ubuntu Server 26.04 LTS image; guest facts unobserved",
            "os": "linux",
            "kernel": "guest-kernel-unobserved",
            "architecture": "x86_64-emulated",
            "libc": "guest-libc-unobserved",
            "abi": "guest-abi-unobserved",
            "filesystem_fixture": "verified-cloud-image-qcow2-overlay",
            "clock_source": "guest-kernel-clock-unobserved",
            "randomness": "guest-entropy-unseeded",
            "scheduler": "guest-kernel-scheduler-uncontrolled",
            "memory_model": "guest-linux-virtual-memory;hardware-ordering-emulated",
            "resource_limits": f"guest-memory={self.memory_mb}MB;limits-unobserved",
            "snapshot_scope": "qcow2-overlay-recreated",
            "network_namespace": "disabled-by-default",
            "syscall_surface": "guest-kernel-unobserved",
        }
        profile = LinuxEnvironmentProfile.from_observed(facts, assumptions=("Ubuntu Server 26.04 LTS guest image", "QEMU TCG q35 machine", "qcow2 overlay recreated for reset"))
        facts.update(profile.facts())
        facts["distribution"] = facts.get("distribution", "Ubuntu Server 26.04 LTS")
        self._profile = profile
        return EnvironmentObservation(
            facts=facts,
            unknown=("guest_kernel", "guest_libc", "guest_abi", "host_hardware", "guest_entropy_seed", "external_services", "guest_scheduler", "guest_clock"),
            redacted_keys=("host_identifiers",),
            profile_id=profile.profile_id,
            capabilities=frozenset({"qemu.tcg", "guest.linux.image", "guest.serial", "guest.snapshot.overlay"}),
        )

    def _check_tools(self) -> None:
        for tool in (self.qemu_command, self.qemu_img_command):
            if not shutil.which(tool) and not Path(tool).exists():
                raise FileNotFoundError(f"QEMU substrate tool is not installed: {tool}")

    def _qemu_version(self) -> str:
        output = subprocess.run([self.qemu_command, "--version"], capture_output=True, text=True, check=True).stdout
        return output.splitlines()[0].strip()

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
