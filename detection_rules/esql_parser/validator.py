# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""ES|QL validator: spawns the Java daemon and exchanges JSON over stdio."""

from __future__ import annotations

import atexit
import contextlib
import itertools
import json
import os
import subprocess
import sys
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VALIDATOR_DIR = DEFAULT_REPO_ROOT / "lib" / "esql-validator"
DEFAULT_ES_HOME = Path("/tmp/elasticsearch")
DEFAULT_INFERENCE_ENDPOINTS_FILE = DEFAULT_VALIDATOR_DIR / "known_inference_endpoints.json"


def _merge_inference_endpoints(
    defaults: list[dict[str, str]], overrides: list[dict[str, str]] | None
) -> list[dict[str, str]]:
    """Merge default and per-call inference endpoints; later entries win on inference_id."""
    by_id: dict[str, dict[str, str]] = {e["inference_id"]: e for e in defaults}
    for entry in overrides or ():
        if "inference_id" in entry and "task_type" in entry:
            by_id[entry["inference_id"]] = entry
    return list(by_id.values())


def _load_default_inference_endpoints(path: Path) -> list[dict[str, str]]:
    """Read the bundled whitelist of known-valid inference endpoints, if present."""
    # Missing or malformed file is non-fatal: callers can still pass endpoints
    # explicitly via validate(..., inference_endpoints=...).
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    out: list[dict[str, str]] = []
    for entry in data.get("endpoints", []):
        if isinstance(entry, dict) and "inference_id" in entry and "task_type" in entry:
            out.append({"inference_id": entry["inference_id"], "task_type": entry["task_type"]})
    return out


class ValidationError(Exception):
    """The daemon itself failed (couldn't start, bad request, crashed)."""


@dataclass
class _DiagnosticEntry:
    """One line/column diagnostic in a validation result."""

    type: str
    message: str
    line: int | None = None
    column: int | None = None

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "_DiagnosticEntry":
        return cls(
            type=payload.get("type", "Unknown"),
            message=payload.get("message", ""),
            line=payload.get("line"),
            column=payload.get("column"),
        )


@dataclass
class ValidationResult:
    """Outcome of validating a single ES|QL query."""

    status: str  # 'ok' | 'parse_error' | 'verify_error' | 'request_error'
    plan: str | None = None
    # Output columns, matching the shape returned by the ES|QL HTTP API:
    # [{"name": "<field>", "type": "<esql_type>"}, ...]. For fields whose underlying ES
    # mapping is unsupported or in conflict, an entry also carries "original_types"
    # (list[str]) and, when one can be inferred, "suggested_cast" (str). Only populated
    # when status == 'ok'.
    columns: list[dict[str, Any]] = field(default_factory=list)
    errors: list[_DiagnosticEntry] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def raise_for_status(self) -> None:
        if self.ok:
            return
        first = self.errors[0] if self.errors else None
        msg = first.message if first else f"status={self.status}"
        loc = f" at line {first.line}:{first.column}" if first and first.line else ""
        raise ValidationError(f"ES|QL {self.status}{loc}: {msg}")


class EsqlValidator:
    """Long-running JVM daemon that parses and verifies ES|QL queries."""

    def __init__(
        self,
        validator_dir: Path | None = None,
        es_home: Path | None = None,
        java_bin: str = "java",
        startup_timeout: float = 60.0,
        request_timeout: float = 30.0,
        build_if_missing: bool = True,
        heap_size: str | None = "512m",
        default_inference_endpoints: list[dict[str, str]] | None = None,
    ) -> None:
        self.validator_dir = Path(validator_dir or DEFAULT_VALIDATOR_DIR)
        self.es_home = Path(es_home or os.environ.get("ES_HOME") or DEFAULT_ES_HOME)
        self.java_bin = java_bin
        self.startup_timeout = startup_timeout
        self.request_timeout = request_timeout
        self.build_if_missing = build_if_missing
        # Cap JVM heap so long-running daemons in bulk validation don't grow unbounded.
        self.heap_size = heap_size
        # Whitelist of inference endpoints to register on every validate() call. The
        # daemon has no live cluster to resolve `.gp-llm-v2-completion` and similar,
        # so we feed in a known-valid set from known_inference_endpoints.json. Pass
        # an explicit list to override (e.g. for tests); pass [] to disable.
        if default_inference_endpoints is None:
            default_inference_endpoints = _load_default_inference_endpoints(
                self.validator_dir / "known_inference_endpoints.json"
            )
        self.default_inference_endpoints = default_inference_endpoints

        self._proc: subprocess.Popen[bytes] | None = None
        self._lock = threading.Lock()
        self._counter = itertools.count(1)
        self._stderr_thread: threading.Thread | None = None
        self._stderr_lines: list[str] = []
        # PID that spawned the current daemon; used to detect fork-inherited state.
        self._started_pid: int | None = None
        self._atexit_registered = False

    # --- public API ---------------------------------------------------------

    def __enter__(self) -> "EsqlValidator":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def start(self) -> None:
        """Build (if needed) and launch the daemon, then wait for the ready handshake."""
        if self._proc is not None:
            return

        jar = self.validator_dir / "build" / "esql-validator.jar"
        classpath_file = self.validator_dir / "build" / "classpath.txt"
        if not jar.exists() or not classpath_file.exists():
            if not self.build_if_missing:
                raise ValidationError(
                    f"Validator JAR not found at {jar}; run lib/esql-validator/build.sh or "
                    f"pass build_if_missing=True."
                )
            self._build()

        classpath = classpath_file.read_text().strip() + ":" + str(jar)
        env = os.environ.copy()
        env.setdefault("RUNTIME_JAVA_HOME", env.get("JAVA_HOME", ""))

        cmd: list[str] = [self.java_bin]
        if self.heap_size:
            cmd.append(f"-Xmx{self.heap_size}")
        cmd.extend(["-cp", classpath, "co.elastic.detectionrules.esqlvalidator.Main"])

        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            bufsize=0,
        )
        self._started_pid = os.getpid()
        if not self._atexit_registered:
            atexit.register(self._atexit_stop)
            self._atexit_registered = True
        assert self._proc.stdout is not None and self._proc.stdin is not None
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, args=(self._proc.stderr,), daemon=True
        )
        self._stderr_thread.start()

        ready = self._read_line(self.startup_timeout)
        try:
            ready_payload = json.loads(ready)
        except json.JSONDecodeError as e:
            self._kill()
            raise ValidationError(f"Daemon emitted non-JSON on startup: {ready!r}") from e
        if ready_payload.get("status") != "ready":
            self._kill()
            raise ValidationError(f"Daemon startup handshake failed: {ready_payload}")

    def stop(self) -> None:
        """Send a graceful shutdown and reap the JVM."""
        if self._proc is None:
            return
        try:
            self._send({"id": "stop", "shutdown": True})
        except (BrokenPipeError, ValidationError):
            pass
        try:
            self._proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        finally:
            self._proc = None
            self._started_pid = None

    def validate(
        self,
        query: str,
        *,
        indices: dict[str, dict[str, Any]] | None = None,
        lookup_indices: dict[str, dict[str, Any]] | None = None,
        enrich_policies: list[dict[str, Any]] | None = None,
        inference_endpoints: list[dict[str, str]] | None = None,
        params: list[Any] | None = None,
    ) -> ValidationResult:
        """Parse and verify an ES|QL query."""
        # indices: {pattern: es_mapping} for FROM targets, e.g. {"logs": {"properties": ...}}.
        # lookup_indices: same shape, for LOOKUP JOIN targets.
        # enrich_policies: list of {name, policy_type, match_field, index, mapping}.
        # inference_endpoints: list of {inference_id, task_type}. Merged with the
        #   bundled whitelist (see default_inference_endpoints); per-call entries win
        #   on inference_id collision.
        # params: positional query params (?).
        request_id = str(next(self._counter))
        payload: dict[str, Any] = {"id": request_id, "query": query}
        if indices:
            payload["indices"] = indices
        if lookup_indices:
            payload["lookup_indices"] = lookup_indices
        if enrich_policies:
            payload["enrich_policies"] = enrich_policies
        merged_inference = _merge_inference_endpoints(self.default_inference_endpoints, inference_endpoints)
        if merged_inference:
            payload["inference_endpoints"] = merged_inference
        if params:
            payload["params"] = params

        response = self._roundtrip(payload)
        if response.get("id") != request_id:
            raise ValidationError(
                f"Out-of-order response: expected id={request_id}, got {response.get('id')}"
            )
        return ValidationResult(
            status=response.get("status", "unknown"),
            plan=response.get("plan"),
            columns=response.get("columns", []),
            errors=[_DiagnosticEntry.from_json(e) for e in response.get("errors", [])],
            raw=response,
        )

    # --- internals ----------------------------------------------------------

    def _build(self) -> None:
        script = self.validator_dir / "build.sh"
        if not script.exists():
            raise ValidationError(f"Build script missing: {script}")
        env = os.environ.copy()
        env["ES_HOME"] = str(self.es_home)
        env.setdefault("RUNTIME_JAVA_HOME", env.get("JAVA_HOME", ""))
        print(
            f"[esql-validator] Building daemon JAR (ES_HOME={self.es_home}). "
            f"First run may take several minutes...",
            file=sys.stderr,
        )
        result = subprocess.run(
            ["bash", str(script)],
            cwd=str(self.validator_dir),
            env=env,
            check=False,
        )
        if result.returncode != 0:
            raise ValidationError(
                f"Build failed (exit {result.returncode}). See {self.validator_dir}/build/gradle-classpath.err"
            )

    def _roundtrip(self, payload: dict[str, Any]) -> dict[str, Any]:
        # One transparent restart if the daemon was inherited across a fork or died
        # since the last call; surface the underlying failure on a second strike.
        last_err: ValidationError | None = None
        with self._lock:
            for attempt in range(2):
                try:
                    self._ensure_alive()
                    self._send(payload)
                    line = self._read_line(self.request_timeout)
                    try:
                        return json.loads(line)
                    except json.JSONDecodeError as e:
                        raise ValidationError(f"Daemon emitted non-JSON: {line!r}") from e
                except (BrokenPipeError, ValidationError) as e:
                    last_err = e if isinstance(e, ValidationError) else ValidationError(str(e))
                    # Force a clean respawn on the next attempt.
                    self._proc = None
                    self._started_pid = None
                    continue
        assert last_err is not None
        raise last_err

    def _ensure_alive(self) -> None:
        """Spawn or respawn the daemon as needed."""
        # Handles three cases: never started, inherited via fork(), and crashed since
        # the last call. Callers (currently _roundtrip) retry once after this.
        if self._proc is None:
            self.start()
            return
        if self._started_pid is not None and self._started_pid != os.getpid():
            # We're in a forked child that inherited the parent's pipes; don't reuse them.
            self._proc = None
            self._started_pid = None
            self._stderr_lines.clear()
            self.start()
            return
        if self._proc.poll() is not None:
            self._proc = None
            self._started_pid = None
            self._stderr_lines.clear()
            self.start()

    def _atexit_stop(self) -> None:
        # Best-effort cleanup on interpreter exit; swallow everything so we never
        # interfere with shutdown.
        try:
            self.stop()
        except Exception:  # noqa: BLE001
            pass

    def _send(self, payload: dict[str, Any]) -> None:
        if self._proc is None or self._proc.stdin is None:
            raise ValidationError("Daemon not started")
        if self._proc.poll() is not None:
            tail = "\n".join(self._stderr_lines[-20:])
            raise ValidationError(f"Daemon died (exit {self._proc.returncode}). stderr:\n{tail}")
        data = (json.dumps(payload) + "\n").encode("utf-8")
        self._proc.stdin.write(data)
        self._proc.stdin.flush()

    def _read_line(self, timeout: float) -> str:
        if self._proc is None or self._proc.stdout is None:
            raise ValidationError("Daemon not started")
        # subprocess.Popen.stdout is a binary stream; we need to read a line with a timeout.
        # Use a thread to enable a timeout (Python doesn't give us select() on pipes on Windows).
        result: list[bytes | BaseException] = []

        def _read() -> None:
            try:
                assert self._proc is not None and self._proc.stdout is not None
                line = self._proc.stdout.readline()
                result.append(line)
            except BaseException as exc:  # noqa: BLE001
                result.append(exc)

        t = threading.Thread(target=_read, daemon=True)
        t.start()
        t.join(timeout)
        if t.is_alive():
            self._kill()
            raise ValidationError(f"Daemon read timed out after {timeout}s")
        if not result:
            raise ValidationError("Daemon EOF without response")
        item = result[0]
        if isinstance(item, BaseException):
            raise ValidationError(f"Daemon read failed: {item}") from item
        if not item:
            tail = "\n".join(self._stderr_lines[-20:])
            raise ValidationError(f"Daemon closed stdout. stderr:\n{tail}")
        return item.decode("utf-8").rstrip("\n")

    def _drain_stderr(self, stream: IO[bytes]) -> None:
        for raw in iter(stream.readline, b""):
            self._stderr_lines.append(raw.decode("utf-8", errors="replace").rstrip("\n"))
            # Bound memory; keep the most recent.
            if len(self._stderr_lines) > 200:
                del self._stderr_lines[: len(self._stderr_lines) - 200]

    def _kill(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            self._proc.kill()


# --- Shared session ---------------------------------------------------------
#
# Keyed by os.getpid() so a child process never reuses a daemon inherited from
# its parent (a fork would have it share the same stdin/stdout pipes, which
# would corrupt the JSON protocol).
_SHARED: dict[int, EsqlValidator] = {}


def get_shared_validator() -> EsqlValidator | None:
    """Return the validator registered for the current process, if any."""
    return _SHARED.get(os.getpid())


@contextlib.contextmanager
def shared_validator(**kwargs: Any) -> Iterator[EsqlValidator]:
    """Scope a single EsqlValidator to a block of work, reused across calls in it."""
    # Re-entrant: an inner `with shared_validator()` yields the outer instance and
    # does not stop it on exit. Used by bulk validation to amortize JVM startup.
    pid = os.getpid()
    existing = _SHARED.get(pid)
    if existing is not None:
        yield existing
        return
    v = EsqlValidator(**kwargs)
    v.start()
    _SHARED[pid] = v
    try:
        yield v
    finally:
        _ = _SHARED.pop(pid, None)
        v.stop()
