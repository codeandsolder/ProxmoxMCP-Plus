# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "proxmoxer>=2.0.1",
#     "requests>=2.31.0",
#     "paramiko>=3.0.0",
# ]
# ///
"""
pxas.py — Monolithic Proxmox scripting helper.

Usage:
    from pxas import px, ct, nt, vt, st, bt
    pxas -c "from pxas import ct; print(ct.get_containers())"
    pxas script.py

All tool methods return native Python dicts/lists. No Content wrappers.
"""

import atexit
import functools
import hashlib
import json
import logging
import os
import platform
import re
import shlex
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import paramiko

logging.basicConfig(
    level=os.environ.get("PXAS_LOG_LEVEL", "WARNING").upper(),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("pxas")

# ---------------------------------------------------------------------------
# 1. WSL / cross-platform path interop
# ---------------------------------------------------------------------------


def _is_wsl() -> bool:
    """Detect if running inside WSL."""
    if platform.system() != "Linux":
        return False
    # Common check: kernel release string contains 'microsoft'
    if "microsoft" in platform.release().lower():
        return True
    # Fallback: check /proc/version
    try:
        if os.path.exists("/proc/version"):
            with open("/proc/version", "r") as f:
                return "microsoft" in f.read().lower()
    except OSError:
        pass
    return False


def _wsl_to_linux_path(win_path: str) -> str:
    """Convert a Windows path (C:\\Users\\...) to its WSL mount equivalent."""
    if not win_path:
        return win_path
    # Already a Linux path
    if win_path.startswith("/") or win_path.startswith("./") or win_path.startswith("../"):
        return win_path
    # Try wslpath if available
    try:
        # Avoid running wslpath if it's already a linux-looking absolute path
        if not (len(win_path) >= 2 and win_path[1] == ":"):
            return win_path
        result = subprocess.run(
            ["wslpath", "-a", win_path],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    # Manual fallback: C:\Users\foo -> /mnt/c/Users/foo
    if len(win_path) >= 2 and win_path[1] == ":":
        drive = win_path[0].lower()
        rest = win_path[2:].replace("\\", "/").lstrip("/")
        return f"/mnt/{drive}/{rest}"
    return win_path


def _expand_env(data: Any) -> Any:
    """Recursively expand ${VAR} references in strings within any JSON-like structure."""
    if isinstance(data, str):
        return os.path.expandvars(data)
    if isinstance(data, dict):
        return {k: _expand_env(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_expand_env(i) for i in data]
    return data


def resolve_path(path: str, ensure_safe: bool = False) -> str:
    """Resolve a path, handling WSL boundary translation and home expansion."""
    if not path:
        return ""
    # Handle WSL boundary if path looks like a Windows path
    if _is_wsl() and (":" in path or "\\" in path):
        path = _wsl_to_linux_path(path)

    p = Path(path).expanduser()
    try:
        resolved = str(p.resolve())
        if ensure_safe and os.name == "posix":
            # For SSH keys etc, ensure 600
            try:
                os.chmod(resolved, 0o600)
            except OSError:
                pass
        return resolved
    except (OSError, RuntimeError):
        # Fallback if resolve fails (e.g. path doesn't exist yet)
        return str(p.absolute())


# ---------------------------------------------------------------------------
# 2. Configuration loading
# ---------------------------------------------------------------------------


class Config:
    """Configuration container."""

    __slots__ = (
        "servers",
        "default_server",
        "proxmox",
        "auth",
        "ssh",
        "allowlist",
        "denylist",
        "loaded_from",
        "checked_paths",
    )

    def __init__(
        self,
        data: Dict[str, Any],
        loaded_from: Optional[str] = None,
        checked_paths: Optional[List[str]] = None,
    ) -> None:
        data = _expand_env(data)
        self.servers: Dict[str, Dict[str, Any]] = data.get("servers", {})
        self.default_server: str = str(data.get("default_server") or "default")
        self.proxmox: Dict[str, Any] = data.get("proxmox", {})
        self.auth: Dict[str, Any] = data.get("auth", {})
        self.ssh: Optional[_SSH] = data.get("ssh")
        self.allowlist: Set[str] = set(str(i) for i in data.get("allowlist", []))
        self.denylist: Set[str] = set(str(i) for i in data.get("denylist", []))
        self.loaded_from: Optional[str] = loaded_from
        self.checked_paths: List[str] = checked_paths or []

        if not self.servers:
            self.servers = {
                self.default_server: {
                    "proxmox": self.proxmox,
                    "auth": self.auth,
                    "ssh": self.ssh,
                    "allowlist": sorted(self.allowlist),
                    "denylist": sorted(self.denylist),
                }
            }
        elif self.default_server not in self.servers:
            self.default_server = next(iter(self.servers))

        default_cfg = self.get_server(self.default_server)
        self.proxmox = default_cfg.get("proxmox", {})
        self.auth = default_cfg.get("auth", {})
        self.ssh = default_cfg.get("ssh")
        self.allowlist = set(str(i) for i in default_cfg.get("allowlist", []))
        self.denylist = set(str(i) for i in default_cfg.get("denylist", []))

    def get_server(self, name: Optional[str] = None) -> Dict[str, Any]:
        server_name = str(name or self.default_server)
        server = self.servers.get(server_name)
        if server is None:
            raise KeyError(
                f"Unknown server {server_name!r}. Available servers: {', '.join(sorted(self.servers))}"
            )
        return server


def _cwd_hash(path: Optional[str] = None) -> str:
    """Generate a SHA-256 hash of the current working directory for ownership tracking."""
    if path is None:
        path = os.getcwd()
    normalized = str(Path(path).resolve())
    if platform.system() == "Windows":
        normalized = normalized.lower().replace("\\", "/")
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def _server_allowlist(server_cfg: Dict[str, Any]) -> Set[str]:
    return set(str(i) for i in server_cfg.get("allowlist", []))


def _server_denylist(server_cfg: Dict[str, Any]) -> Set[str]:
    denylist = set(str(i) for i in server_cfg.get("denylist", []))
    denylist.add("new")
    return denylist


def _is_allowed(identifier: str, server_cfg: Dict[str, Any]) -> Tuple[bool, str]:
    """Check if an identifier is allowed by config. Returns (allowed, reason)."""
    denylist = _server_denylist(server_cfg)
    allowlist = _server_allowlist(server_cfg)
    if identifier in denylist:
        return False, f"'{identifier}' is in denylist"
    if allowlist:
        if identifier in allowlist:
            return True, f"'{identifier}' is in allowlist"
        return False, f"'{identifier}' is not in allowlist"
    if identifier == "new":
        return False, "'new' is in denylist by default"
    return True, "allowed by default"


def _check_allowed(
    identifier: str,
    label: str,
    server_cfg: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Return error dict if not allowed, else None."""
    allowed, reason = _is_allowed(identifier, server_cfg)
    if not allowed:
        return {
            "error": True,
            "reason": f"Access denied: {label} ({identifier}) - {reason}",
            "fix": "Ask the user to update the per-server allowlist/denylist in config to allow this operation.",
        }
    return None


def _check_access(
    identifier: str,
    label: str,
    server_cfg: Dict[str, Any],
    owned_hashes: Dict[str, str],
    node: Optional[str] = None,
    vmid: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Check if identifier (and optionally node) is restricted. Returns error dict if blocked."""
    if vmid and str(vmid) in owned_hashes:
        return None
    err = _check_allowed(identifier, label, server_cfg)
    if err:
        return err
    if node and node != identifier:
        return _check_allowed(node, node, server_cfg)
    return None


def _add_restricted_flag(
    identifier: str, server_cfg: Dict[str, Any], owned_hashes: Dict[str, str]
) -> bool:
    """Return True if identifier is restricted by config rules."""
    if identifier in owned_hashes:
        return False
    allowed, _ = _is_allowed(identifier, server_cfg)
    return not allowed


class _SSH:
    __slots__ = (
        "user",
        "port",
        "key_file",
        "password",
        "host_overrides",
        "use_sudo",
        "strict_host_key_checking",
    )

    def __init__(self, d: Dict[str, Any]) -> None:
        self.user: str = d.get("user", "root")
        self.port: int = int(d.get("port", 22))
        key_file = d.get("key_file")
        self.key_file: Optional[str] = (
            resolve_path(key_file, ensure_safe=True) if key_file else None
        )
        self.password: Optional[str] = d.get("password")
        self.host_overrides: Dict[str, str] = d.get("host_overrides", {})
        self.use_sudo: bool = bool(d.get("use_sudo", False))
        self.strict_host_key_checking: bool = bool(d.get("strict_host_key_checking", False))


def _load_ssh_config(raw: Dict[str, Any]) -> Optional[_SSH]:
    """Load SSH config as a simple namespace object."""
    if not raw:
        return None
    return _SSH(raw)


def _get_windows_home_in_wsl() -> Optional[Path]:
    """Guess Windows user home directory from WSL."""
    if not _is_wsl():
        return None
    # 1. Try environment variable inherited from Windows
    win_profile = os.environ.get("USERPROFILE")
    if win_profile:
        p = Path(_wsl_to_linux_path(win_profile))
        if p.is_dir():
            return p
    # 2. Infer from WSL user name
    user = os.environ.get("USER")
    if user:
        p = Path(f"/mnt/c/Users/{user}")
        if p.is_dir():
            return p
    # 3. Check for common mount points
    for drive in ("c", "d"):
        users_dir = Path(f"/mnt/{drive}/Users")
        if users_dir.is_dir():
            user = os.environ.get("USER")
            if user and (users_dir / user).is_dir():
                return users_dir / user
    return None


def _load_config(extra_dirs: Optional[List[Path]] = None) -> Config:
    script_dir = Path(__file__).resolve().parent
    config_path = os.environ.get("PROXMOX_CONFIG")
    found_at: Optional[str] = None

    # Track paths for the error message
    checked_paths: List[str] = [
        "PROXMOX_HOST environment variable",
        "PROXMOX_CONFIG environment variable",
    ]

    if not config_path:
        candidates = []

        # 1. Project-specific: .claude/skills/proxmox/config.json (from project root, above .claude)
        candidates.append(Path.cwd() / ".claude" / "skills" / "proxmox" / "config.json")
        candidates.append(Path.cwd() / ".agents" / "skills" / "proxmox" / "config.json")

        # 2. Explicit extra dirs
        candidates.extend([d / "config.json" for d in (extra_dirs or [])])

        # 3. Bundled config: Directory where pxas.py lives (via uv/hatchling)
        candidates.append(script_dir / "config.json")

        # 4. Fallback: Standard global user config
        candidates.append(Path.home() / ".config" / "proxmox" / "config.json")
        candidates.append(Path.home() / ".claude" / "skills" / "proxmox" / "config.json")
        candidates.append(Path.home() / ".agents" / "skills" / "proxmox" / "config.json")

        # 5. Fallback: Windows home if running inside WSL
        win_home = _get_windows_home_in_wsl()
        if win_home:
            candidates.append(win_home / ".config" / "proxmox" / "config.json")
            candidates.append(win_home / ".claude" / "skills" / "proxmox" / "config.json")
            candidates.append(win_home / ".agents" / "skills" / "proxmox" / "config.json")

        # Store string representations of the paths checked
        for c in candidates:
            checked_paths.append(str(c))

        # Find the first one that exists
        for candidate in candidates:
            if candidate.is_file():
                config_path = str(candidate)
                found_at = config_path
                break

    if not config_path:
        config_path = str(Path.home() / ".config" / "proxmox" / "config.json")

    config_path = resolve_path(config_path)

    config_data: Dict[str, Any] = {}
    if os.path.exists(config_path):
        found_at = config_path
        with open(config_path) as f:
            try:
                config_data = json.load(f)
            except json.JSONDecodeError as e:
                logger.error("Failed to parse config at %s: %s", config_path, e)
    else:
        config_data = {
            "proxmox": {
                "host": os.getenv("PROXMOX_HOST"),
                "port": int(os.getenv("PROXMOX_PORT", "8006"))
                if os.getenv("PROXMOX_PORT")
                else 8006,
                "verify_ssl": os.getenv("PROXMOX_VERIFY_SSL", "false").lower() == "true",
                "service": os.getenv("PROXMOX_SERVICE", "PVE"),
            },
            "auth": {
                "user": os.getenv("PROXMOX_USER"),
                "token_name": os.getenv("PROXMOX_TOKEN_NAME"),
                "token_value": os.getenv("PROXMOX_TOKEN_VALUE"),
            },
            "ssh": {
                "user": os.getenv("PROXMOX_SSH_USER"),
                "key_file": os.getenv("PROXMOX_SSH_KEY"),
                "password": os.getenv("PROXMOX_SSH_PASSWORD"),
            },
        }

    ssh_raw = config_data.get("ssh", {})
    config_data["ssh"] = _load_ssh_config(ssh_raw) if ssh_raw else None

    servers_raw = config_data.get("servers", {})
    servers: Dict[str, Dict[str, Any]] = {}
    if isinstance(servers_raw, dict):
        for server_name, server_data in servers_raw.items():
            if not isinstance(server_data, dict):
                continue
            server_ssh = server_data.get("ssh", {})
            denylist = [str(i) for i in server_data.get("denylist", [])]
            if "new" not in denylist:
                denylist.append("new")
            servers[str(server_name)] = {
                "proxmox": server_data.get("proxmox", {}),
                "auth": server_data.get("auth", {}),
                "ssh": _load_ssh_config(server_ssh) if server_ssh else None,
                "allowlist": [str(i) for i in server_data.get("allowlist", [])],
                "denylist": denylist,
            }
    if servers:
        config_data["servers"] = servers

    if not servers:
        denylist = [str(i) for i in config_data.get("denylist", [])]
        if "new" not in denylist:
            denylist.append("new")
        config_data["denylist"] = denylist
        config_data["allowlist"] = [str(i) for i in config_data.get("allowlist", [])]

    return Config(config_data, loaded_from=found_at, checked_paths=checked_paths)


def _load_ownership_hashes(px: Any) -> Dict[str, str]:
    """Scan all containers and VMs, extract pxas:owned hashes into _owned_hashes."""
    owned_hashes: Dict[str, str] = {}
    try:
        nodes = [_get(n, "node") for n in _as_list(px.nodes.get()) if _get(n, "node")]
    except Exception:
        return owned_hashes
    for node in nodes:
        for resource_type in ("lxc", "qemu"):
            try:
                items = _as_list(getattr(px.nodes(node), resource_type).get())
            except Exception:
                continue
            for item in items:
                vmid = _get(item, "vmid")
                if not vmid:
                    continue
                try:
                    desc = _as_dict(getattr(px.nodes(node), resource_type)(vmid).config.get()).get(
                        "description", ""
                    )
                    marker = "pxas:owned"
                    if marker not in desc:
                        continue
                    for part in desc.split(marker):
                        if "hash=" in part:
                            stored_hash = part.split("hash=")[-1].split("|")[0].strip()
                            owned_hashes[str(vmid)] = stored_hash
                            break
                except Exception:
                    continue
    return owned_hashes


# ---------------------------------------------------------------------------
# 3. Error context injection decorator
# ---------------------------------------------------------------------------


_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "token_value",
        "token",
        "secret",
        "private_key",
        "api_key",
        "secret_key",
        "auth_token",
        "passphrase",
    }
)


def _error_dict(func: Callable, args: tuple, kwargs: dict, exc: Exception) -> Dict[str, Any]:
    """Build a structured error dict from an exception."""
    fn = getattr(func, "__name__", repr(func))
    func_name = f"{args[0].__class__.__name__}.{fn}" if args else fn
    error_msg = str(exc).strip()
    low = error_msg.lower()
    if "not found" in low or "does not exist" in low:
        fix = "Verify the node name, VMID, and that the resource exists on the correct node."
    elif "permission denied" in low or "403" in low:
        fix = "Verify API token has sufficient privileges (PVEAuditor or PVEAdmin)."
    elif "timed out" in low or "timeout" in low:
        fix = "The operation timed out. Increase timeout_s or check network connectivity."
    elif "ssh" in low:
        fix = "Verify SSH key path and node accessibility. cfg.ssh must be configured for exec."
    elif "already" in low and "exist" in low:
        fix = "Use a different VMID or delete the existing resource first."
    elif "not running" in low:
        fix = "Start the container/VM before executing commands inside it."
    else:
        fix = "Check that the target resource exists and credentials are valid."
    logger.error("%s failed: %s", func_name, error_msg)
    safe_params = {
        k: ("<redacted>" if k.lower() in _SENSITIVE_KEYS else str(v)[:200])
        for k, v in kwargs.items()
    }
    return {
        "error": True,
        "function": func_name,
        "reason": error_msg,
        "params": safe_params,
        "fix": fix,
    }


def px_error(func: Callable) -> Callable:
    """Decorator for query methods — catches exceptions, returns structured error dict."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            return _error_dict(func, args, kwargs, exc)

    return wrapper


def px_op(func: Callable) -> Callable:
    """Decorator for mutating operations — returns (success: bool, data: dict|list).

    Splits the 'success' key out of result dicts so callers can do:
        ok, info = vt.start_vm(node, vmid)
    Exceptions become (False, error_dict).
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Tuple[bool, Any]:
        try:
            result = func(*args, **kwargs)
        except Exception as exc:
            return False, _error_dict(func, args, kwargs, exc)
        if isinstance(result, dict):
            if result.get("error"):
                return False, result
            ok = bool(result.get("success", True))
            return ok, {k: v for k, v in result.items() if k != "success"}
        if isinstance(result, list):
            all_ok = all(r.get("success", True) for r in result if isinstance(r, dict))
            clean = [
                {k: v for k, v in r.items() if k != "success"} if isinstance(r, dict) else r
                for r in result
            ]
            return all_ok, clean
        return True, result

    return wrapper


# ---------------------------------------------------------------------------
# 4. Data helpers
# ---------------------------------------------------------------------------


def _unwrap(raw: Any) -> Any:
    """Unwrap {'data': ...} envelopes from proxmoxer responses."""
    if isinstance(raw, dict):
        data = raw.get("data")
        if data is not None:
            return data
    return raw


def _as_list(raw: Any) -> List[Any]:
    v = _unwrap(raw)
    return v if isinstance(v, list) else []


def _as_dict(raw: Any) -> Dict[str, Any]:
    v = _unwrap(raw)
    return v if isinstance(v, dict) else {}


def _get(d: Any, key: str, default: Any = None) -> Any:
    return d.get(key, default) if isinstance(d, dict) else default


def _b2h(n: int | float | str) -> str:
    """Bytes to human-readable string."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "0 B"
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    i = 0
    while n >= 1024.0 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    return f"{n:.2f} {units[i]}"


def _round(v: float | int, places: int = 2) -> float | int:
    """Round floats to N decimal places; pass through ints."""
    if isinstance(v, float):
        return round(v, places)
    return v


# ---------------------------------------------------------------------------
# 5. Task wait and log helpers
# ---------------------------------------------------------------------------


def _get_task_status(proxmox_api: Any, node: str, upid: str) -> Dict[str, Any]:
    """Get status of a running/finished task by its UPID."""
    try:
        return _as_dict(proxmox_api.nodes(node).tasks(upid).status.get())
    except Exception:
        return {}


def _get_task_log(proxmox_api: Any, node: str, upid: str) -> str:
    """Get log output lines for a completed task."""
    try:
        log = _as_list(proxmox_api.nodes(node).tasks(upid).log.get())
        return "\n".join(entry.get("t", "") for entry in log if isinstance(entry, dict))
    except Exception:
        return ""  # Task log is optional enrichment; missing or inaccessible log is non-fatal


def _prune_output(output: str, max_lines: int = 50) -> str:
    """Remove repetitive progress lines from task output, keeping meaningful content.

    Strips lines matching common verbose patterns (progress %, read/write stats,
    vma extract progress) and truncates to max_lines if still too long.
    """
    _VERBOSE_PATTERNS = re.compile(
        r"^(progress \d+%|"
        r"p\s*$|"  # truncated progress lines
        r"\s*\d+\s*%.*\(read \d+|"  # vzdump read progress
        r"map '.*' to '.*'|"
        r"new volume ID is '.*'|"
        r"CTIME:|DEV:|CFG:|"
        r".*- this may take some time \.\.\.|"
        r"status: \d+/\d+ bytes|"  # more generic progress
        r"\s+\d+\s+of\s+\d+\s+blocks|"  # zfs/vzdump
        r"total bytes (read|written):|"  # summary stats
        r"transfer rate:|"
        r"compressing.*with zstd"  # vzdump zstd info
        r")",
        re.IGNORECASE,
    )
    _KEEP_PATTERNS = re.compile(
        r"(error|fail|reject|denied|wrong|invalid|missing|fatal|warning|alert|critical)",
        re.IGNORECASE,
    )

    lines = output.splitlines()
    pruned = [
        line for line in lines if not _VERBOSE_PATTERNS.match(line) or _KEEP_PATTERNS.search(line)
    ]
    if len(pruned) > max_lines:
        half = max_lines // 2
        pruned = (
            pruned[:half] + [f"... ({len(pruned) - max_lines} lines omitted) ..."] + pruned[-half:]
        )
    return "\n".join(pruned)


def _check_vmid_free(proxmox_api: Any, vmid: int) -> Optional[Dict[str, Any]]:
    """Return an error dict if vmid is already in use (any type, any node), else None."""
    try:
        resources = _as_list(proxmox_api.cluster.resources.get())
    except Exception:
        resources = []
    for r in resources:
        if str(_get(r, "vmid")) == str(vmid):
            rtype = _get(r, "type", "resource")
            rnode = _get(r, "node", "unknown")
            return {
                "error": True,
                "reason": f"VMID {vmid} already in use by a {rtype} on node {rnode}",
                "fix": "Use a different VMID or delete the existing resource first.",
            }
    return None


def _wait_task(proxmox_api: Any, node: str, upid: str, timeout: int = 300) -> Dict[str, Any]:
    """Poll a task until finished. Returns:
    {"success": bool, "upid": str, "output": str, "elapsed": float}
    """
    start = time.monotonic()
    deadline = start + timeout
    while time.monotonic() < deadline:
        info = _get_task_status(proxmox_api, node, upid)
        status = info.get("status", "")
        if status and status != "running":
            elapsed = _round(time.monotonic() - start)
            log = _get_task_log(proxmox_api, node, upid)
            ok = status.upper() == "OK"
            output = log.removesuffix("\nTASK OK").removesuffix("TASK OK").strip() if ok else log
            return {
                "success": ok,
                "upid": upid,
                "output": _prune_output(output),
                "elapsed": elapsed,
            }
        time.sleep(2)
    elapsed = _round(time.monotonic() - start)
    log = _get_task_log(proxmox_api, node, upid)
    return {
        "success": False,
        "upid": upid,
        "output": _prune_output(log),
        "elapsed": elapsed,
    }


def _is_permanent_error(msg: str) -> bool:
    """Return True if the error message indicates a condition that won't resolve on retry."""
    low = msg.lower()
    permanent_phrases = (
        "does not exist",
        "not found",
        "no such",
        "already exists",
        "already running",
        "already stopped",
        "permission denied",
        "forbidden",
        "unauthorized",
        "insufficient privilege",
        "invalid parameter",
        "invalid value",
        "bad request",
        "400 ",
        "403 ",
        "404 ",
        "409 ",
    )
    # Lock/contention errors are transient — Proxmox serialises ops with locks
    if "lock" in low or "locked" in low:
        return False
    return any(p in low for p in permanent_phrases)


def _run_with_retry(
    proxmox_api: Any,
    node: str,
    action: Callable,
    wait: bool,
    retry: bool,
    timeout_s: int,
) -> Dict[str, Any]:
    """Execute action(), poll task, retry on transient failures if under timeout.

    action: callable returning a task UPID string (the API call).
    Returns _wait_task result dict.
    """
    if not wait:
        try:
            return action()
        except Exception as e:
            # Not going through _error_dict: no func/args context here; caller's @px_op
            # wrapper has already returned by the time this runs, so log directly.
            logger.error("API call failed (wait=False): %s", e)
            return {"error": True, "reason": str(e)}
    deadline = time.monotonic() + timeout_s
    attempt = 0
    while True:
        attempt += 1
        try:
            upid = action()
        except Exception as e:
            err = str(e)
            if retry and not _is_permanent_error(err) and time.monotonic() < deadline - 2:
                time.sleep(2)
                continue
            logger.error("API call failed after %d attempt(s): %s", attempt, err)
            return {
                "success": False,
                "reason": err,
                "output": "",
                "elapsed": 0,
                "attempts": attempt,
            }
        remaining = int(max(deadline - time.monotonic(), 1))
        r = _wait_task(proxmox_api, node, upid, remaining)
        r["attempts"] = attempt
        if r["success"] or not retry or time.monotonic() >= deadline - 2:
            return r
        # Also skip retry if the task output signals a permanent failure
        if _is_permanent_error(r.get("output", "")):
            return r
        time.sleep(2)


# ---------------------------------------------------------------------------
# 6. Base Tools
# ---------------------------------------------------------------------------


def _resolve_selector(
    selector: str | int | List[str | int],
    inventory: List[Tuple[str, Dict]],
) -> List[Tuple[str, int, str]]:
    """Turn a selector into [(node, vmid, label), ...].

    Accepts: int (vmid), str vmid, 'node:vmid', 'node/name', 'name',
    comma-separated combinations, or a list.
    """
    if not selector:
        return []
    if isinstance(selector, list):
        tokens = [str(t).strip() for t in selector if str(t).strip()]
    else:
        tokens = [t.strip() for t in str(selector).split(",") if t.strip()]

    def _label(res: Dict, vid: int) -> str:
        return _get(res, "name") or _get(res, "hostname") or f"id-{vid}"

    # Build lookup indices once for O(1) access per token
    by_vmid: Dict[int, List[Tuple[str, Dict]]] = {}
    by_node_vmid: Dict[Tuple[str, int], List[Tuple[str, Dict]]] = {}
    by_name: Dict[str, List[Tuple[str, Dict]]] = {}
    by_node_name: Dict[Tuple[str, str], List[Tuple[str, Dict]]] = {}
    for nd, res in inventory:
        vid = int(_get(res, "vmid", -1))
        nm = _get(res, "name") or _get(res, "hostname") or ""
        if vid > 0:
            by_vmid.setdefault(vid, []).append((nd, res))
            by_node_vmid.setdefault((nd, vid), []).append((nd, res))
        if nm:
            by_name.setdefault(nm, []).append((nd, res))
            by_node_name.setdefault((nd, nm), []).append((nd, res))

    def _match(tok: str) -> List[Tuple[str, int, str]]:
        # node:vmid
        if ":" in tok:
            n, v = tok.split(":", 1)
            try:
                vid = int(v)
            except ValueError:
                return []
            return [(nd, vid, _label(res, vid)) for nd, res in by_node_vmid.get((n, vid), [])]
        # node/name
        if "/" in tok:
            n, nm = tok.split("/", 1)
            return [
                (nd, int(_get(res, "vmid")), nm)
                for nd, res in by_node_name.get((n, nm), [])
                if _get(res, "vmid") is not None
            ]
        # vmid only
        if tok.isdigit():
            vid = int(tok)
            return [(nd, vid, _label(res, vid)) for nd, res in by_vmid.get(vid, [])]
        # name only
        return [
            (nd, int(_get(res, "vmid")), tok)
            for nd, res in by_name.get(tok, [])
            if _get(res, "vmid") is not None
        ]

    resolved: List[Tuple[str, int, str]] = []
    for tok in tokens:
        resolved.extend(_match(tok))

    # deduplicate by (node, vmid), keeping last label
    seen: Dict[Tuple[str, int], str] = {}
    for n, v, lbl in resolved:
        seen[(n, v)] = lbl
    return [(n, v, lbl) for (n, v), lbl in seen.items()]


class _BaseTools:
    """Base class for Resource Tools with common selector and listing logic."""

    def __init__(
        self,
        proxmox_api: Any,
        server_cfg: Optional[Dict[str, Any]] = None,
        owned_hashes: Optional[Dict[str, str]] = None,
    ) -> None:
        self.px = proxmox_api
        self.server_cfg = server_cfg or {}
        self.owned_hashes = owned_hashes if owned_hashes is not None else {}

    _target_type: str = "targets"
    _resource_type: str = ""  # "lxc" or "qemu" — set by subclass

    def _check_restriction(
        self, identifier: str, label: str, node: Optional[str] = None, vmid: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Check if an identifier is restricted. Returns error dict if blocked, else None."""
        return _check_access(identifier, label, self.server_cfg, self.owned_hashes, node, vmid)

    def _add_restricted_flag(self, identifier: str) -> bool:
        """Check if an identifier is restricted. Returns True if restricted."""
        return _add_restricted_flag(identifier, self.server_cfg, self.owned_hashes)

    def _store_ownership_hash(self, node: str, vmid: str, resource_type: str) -> None:
        """Store the current working directory hash in the container/VM description."""
        try:
            path_hash = _cwd_hash()
            cwd = os.getcwd()
            existing = _as_dict(getattr(self.px.nodes(node), resource_type)(vmid).config.get()).get(
                "description", ""
            )
            marker = "pxas:owned"
            if marker in existing:
                before, _, after = existing.partition(marker)
                existing = before.rstrip()
                after_marker = after.split("|", 1)[-1] if "|" in after else ""
                if after_marker:
                    existing = f"{existing} {after_marker}".strip()
            new_desc = f"{existing} {marker} path={cwd}|hash={path_hash}".strip()
            getattr(self.px.nodes(node), resource_type)(vmid).config.put(description=new_desc)
            self.owned_hashes[str(vmid)] = path_hash
        except Exception:
            pass

    def _list_pairs(self, node: Optional[str] = None) -> List[Tuple[str, Dict]]:
        """Return [(node_name, resource_dict), ...] for all or one node."""
        out: List[Tuple[str, Dict]] = []
        try:
            nodes_to_query = (
                [node]
                if node
                else [_get(n, "node") for n in _as_list(self.px.nodes.get()) if _get(n, "node")]
            )
        except Exception:
            return out  # Node list unavailable; return empty
        for n in nodes_to_query:
            try:
                items = _as_list(getattr(self.px.nodes(n), self._resource_type).get())
            except Exception:
                continue  # Individual node may be offline; skip and enumerate the rest
            for it in items:
                if isinstance(it, dict):
                    out.append((n, it))
                else:
                    try:
                        out.append((n, {"vmid": int(it)}))
                    except (TypeError, ValueError):
                        pass
        return out

    def _resolve(self, selector: str | int | List[str | int]) -> List[Tuple[str, int, str]]:
        """Turn selector into [(node, vmid, label), ...]."""
        return _resolve_selector(selector, self._list_pairs())

    def _batch_action(
        self,
        selector: str | int | List[str | int],
        action: Callable[[str, int], Any],
        pre_check: Optional[Callable[[str, int, str], Optional[Dict[str, Any]]]] = None,
        wait: bool = True,
        retry: bool = True,
        timeout_s: int = 60,
    ) -> Dict[str, Any] | List[Dict[str, Any]]:
        """Run an action on resolved targets with optional pre_check and retries."""
        targets = self._resolve(selector)
        if not targets:
            return {"error": True, "reason": f"No {self._target_type} matched selector: {selector}"}
        results = []
        for node, vmid, label in targets:
            restricted = self._check_restriction(str(vmid), label, node, vmid)
            if restricted:
                results.append(restricted)
                continue
            if pre_check:
                check_result = pre_check(node, vmid, label)
                if check_result:
                    results.append(check_result)
                    continue
            res: Dict[str, Any] = {"node": node, "vmid": str(vmid), "name": label}
            r = _run_with_retry(
                self.px,
                node,
                lambda n=node, v=vmid: action(n, v),
                wait=wait,
                retry=retry,
                timeout_s=timeout_s,
            )
            if wait:
                res["success"] = r.get("success", False)
                res["output"] = r.get("output", "")
                res["elapsed"] = r.get("elapsed", 0)
            else:
                res["success"] = "error" not in r
                res["status"] = "initiated"
                res["task"] = r if isinstance(r, str) else r.get("error", "")
            results.append(res)
        return results


# ---------------------------------------------------------------------------
# 7. SSH + pct exec engine (fortified)
# ---------------------------------------------------------------------------


class ContainerExec:
    """Execute commands inside LXC containers via SSH + pct exec.

    - All commands are shlex.quoted to prevent injection.
    - stdout and stderr are returned as separate keys.
    - timeout is a dynamic parameter per call.
    - SSH connections are pooled per node and reused across calls.
    """

    def __init__(self, proxmox_api: Any, ssh_config: _SSH) -> None:
        self.proxmox = proxmox_api
        self.ssh = ssh_config
        self._pool: Dict[str, paramiko.SSHClient] = {}

    def _ssh_host(self, node: str) -> str:
        if self.ssh and self.ssh.host_overrides:
            return self.ssh.host_overrides.get(node, node)
        return node

    def _connect(self, node: str) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        policy = (
            paramiko.RejectPolicy()
            if self.ssh.strict_host_key_checking
            else paramiko.AutoAddPolicy()
        )
        client.set_missing_host_key_policy(policy)
        kw: Dict[str, str | int] = dict(
            hostname=self._ssh_host(node),
            port=self.ssh.port,
            username=self.ssh.user,
            timeout=10,
        )
        if self.ssh.key_file:
            kw["key_filename"] = resolve_path(self.ssh.key_file)
        elif self.ssh.password:
            kw["password"] = self.ssh.password
        client.connect(**kw)
        return client

    def _get_connection(self, node: str) -> paramiko.SSHClient:
        """Get a pooled SSH connection for a node, creating one if needed."""
        client = self._pool.get(node)
        if client is not None:
            transport = client.get_transport()
            if transport and transport.is_active():
                return client
            # Stale connection — close and replace
            try:
                client.close()
            except Exception:
                pass  # Closing a dead connection may fail; swallow and reconnect
        client = self._connect(node)
        self._pool[node] = client
        return client

    def close(self) -> None:
        """Close all pooled SSH connections."""
        for client in self._pool.values():
            try:
                client.close()
            except Exception:
                pass  # Best-effort pool teardown; individual close failures are ignored
        self._pool.clear()

    @px_error
    def run(self, node: str, vmid: str, command: str, timeout: int = 60) -> Dict[str, Any]:
        """Run a command inside container. Returns:
        {"success": bool, "output": str, "error": str, "exit_code": int}
        """
        status = self.proxmox.nodes(node).lxc(vmid).status.current.get()
        if _get(status, "status") != "running":
            return {
                "error": True,
                "reason": f"Container {vmid} on {node} is not running",
                "fix": "Start the container before executing commands.",
            }
        prefix = "sudo " if self.ssh.use_sudo else ""
        pct_cmd = (
            f"{prefix}/usr/sbin/pct exec {shlex.quote(str(vmid))} -- sh -c {shlex.quote(command)}"
        )
        client = self._get_connection(node)
        try:
            _, stdout, stderr = client.exec_command(pct_cmd, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            exit_code = stdout.channel.recv_exit_status()
            return {
                "success": exit_code == 0,
                "output": out,
                "error": err,
                "exit_code": exit_code,
            }
        except (paramiko.SSHException, OSError):
            # Stale connection — evict and retry once
            self._pool.pop(node, None)
            client = self._get_connection(node)
            _, stdout, stderr = client.exec_command(pct_cmd, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            exit_code = stdout.channel.recv_exit_status()
            return {
                "success": exit_code == 0,
                "output": out,
                "error": err,
                "exit_code": exit_code,
            }

    @px_error
    def wait_until(
        self,
        node: str,
        vmid: str,
        command: str,
        timeout_s: int = 300,
        interval_s: int = 5,
    ) -> Dict[str, Any]:
        """Poll command until exit 0 or timeout. Returns:
        {"matched": bool, "attempts": int, "elapsed": float,
         "last_output": str, "last_exit_code": int}
        """
        timeout_s = min(max(timeout_s, 1), 3600)
        interval_s = max(interval_s, 1)

        status = self.proxmox.nodes(node).lxc(vmid).status.current.get()
        if _get(status, "status") != "running":
            return {
                "error": True,
                "reason": f"Container {vmid} on {node} is not running",
            }

        prefix = "sudo " if self.ssh.use_sudo else ""
        pct_cmd = (
            f"{prefix}/usr/sbin/pct exec {shlex.quote(str(vmid))} -- sh -c {shlex.quote(command)}"
        )
        client = self._get_connection(node)
        attempts = 0
        last_output = ""
        last_exit_code = -1
        start = time.monotonic()
        deadline = start + timeout_s

        while time.monotonic() < deadline:
            attempts += 1
            try:
                _, stdout, _ = client.exec_command(pct_cmd, timeout=max(interval_s * 3, 30))
                last_output = stdout.read().decode("utf-8", errors="replace").strip()
                last_exit_code = stdout.channel.recv_exit_status()
            except (paramiko.SSHException, OSError):
                # Stale connection — evict, reconnect, and continue polling
                self._pool.pop(node, None)
                try:
                    client = self._get_connection(node)
                except Exception as reconnect_err:
                    last_output = str(reconnect_err)
                    last_exit_code = -1
                continue

            if last_exit_code == 0:
                elapsed = _round(time.monotonic() - start)
                return {
                    "matched": True,
                    "attempts": attempts,
                    "elapsed": elapsed,
                    "last_output": last_output,
                    "last_exit_code": last_exit_code,
                }

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(interval_s, remaining))

        elapsed = _round(time.monotonic() - start)
        return {
            "matched": False,
            "attempts": attempts,
            "elapsed": elapsed,
            "last_output": last_output,
            "last_exit_code": last_exit_code,
        }


# ---------------------------------------------------------------------------
# 8. ContainerTools
# ---------------------------------------------------------------------------


class ContainerTools(_BaseTools):
    """LXC container operations — all methods return native dicts/lists."""

    _target_type = "containers"
    _resource_type = "lxc"

    def __init__(
        self,
        proxmox_api: Any,
        ssh_config: Optional[_SSH] = None,
        server_cfg: Optional[Dict[str, Any]] = None,
        owned_hashes: Optional[Dict[str, str]] = None,
    ) -> None:
        super().__init__(proxmox_api, server_cfg=server_cfg, owned_hashes=owned_hashes)
        self.exec_ = ContainerExec(proxmox_api, ssh_config) if ssh_config else None
        self.log = logging.getLogger("pxas.ct")

    def close(self) -> None:
        """Close pooled SSH connections."""
        if self.exec_:
            self.exec_.close()

    # -- internal helpers --

    def _rrd_last(
        self, node: str, vmid: int
    ) -> Tuple[Optional[float], Optional[int], Optional[int]]:
        try:
            rrd = _as_list(
                self.px.nodes(node).lxc(vmid).rrddata.get(timeframe="hour", ds="cpu,mem,maxmem")
            )
            if not rrd or not isinstance(rrd[-1], dict):
                return None, None, None
            last = rrd[-1]
            return (
                _round(float(_get(last, "cpu", 0) or 0) * 100.0),
                int(_get(last, "mem", 0) or 0),
                int(_get(last, "maxmem", 0) or 0),
            )
        except Exception:
            return (
                None,
                None,
                None,
            )  # RRD data unavailable during state transitions; caller treats None as missing

    def _status_config(self, node: str, vmid: int) -> Tuple[Dict, Dict]:
        try:
            s = _as_dict(self.px.nodes(node).lxc(vmid).status.current.get())
        except Exception:
            s = {}  # Status may be unavailable during container state transitions
        try:
            c = _as_dict(self.px.nodes(node).lxc(vmid).config.get())
        except Exception:
            c = {}  # Config may be unavailable for containers in error state
        return s, c

    # -- flattened container record (token-optimized) --

    def _flatten_ct(self, node: str, ct: Dict, include_stats: bool, realtime: bool = False) -> Dict:
        """Build a flat, token-optimized container record."""
        vmid_raw = _get(ct, "vmid")
        vmid_int = int(vmid_raw) if vmid_raw is not None else None
        rec: Dict[str, Any] = {
            "vmid": str(vmid_raw) if vmid_raw is not None else None,
            "name": _get(ct, "name")
            or _get(ct, "hostname")
            or (f"ct-{vmid_raw}" if vmid_raw else "ct-?"),
            "node": node,
            "status": _get(ct, "status"),
        }
        if not include_stats or vmid_int is None:
            if vmid_raw is not None:
                rec["restricted"] = self._add_restricted_flag(str(vmid_raw))
            return rec
        raw_s, raw_c = self._status_config(node, vmid_int)
        cpu_pct = _round(float(_get(raw_s, "cpu", 0) or 0) * 100.0)
        mem_bytes = int(_get(raw_s, "mem", 0) or 0)
        maxmem_bytes = int(_get(raw_s, "maxmem", 0) or 0)
        status_str = str(_get(raw_s, "status") or _get(ct, "status") or "").lower()
        if status_str == "stopped":
            mem_bytes = 0

        mem_mib = 0
        cores = None
        _mem_key_found = False
        for key in ("memory", "ram", "maxmem", "memoryMiB"):
            val = _get(raw_c, key)
            if val is not None:
                _mem_key_found = True
                try:
                    mem_mib = int(val)
                except (TypeError, ValueError):
                    pass
                break
        # In Proxmox LXC config, memory=0 means unlimited. If no memory key is
        # present at all we also treat it as unlimited (no configured cap).
        unlimited = not _mem_key_found or mem_mib == 0
        cores_raw = _get(raw_c, "cores")
        cpulimit_raw = _get(raw_c, "cpulimit")
        if cores_raw is not None:
            try:
                cores = int(cores_raw)
            except (TypeError, ValueError):
                pass
        elif cpulimit_raw is not None:
            try:
                if float(cpulimit_raw) > 0:
                    cores = _round(float(cpulimit_raw))
            except (TypeError, ValueError):
                pass

        if (maxmem_bytes is None or maxmem_bytes == 0) and mem_mib > 0:
            maxmem_bytes = mem_mib * 1024 * 1024

        should_fetch_rrd = not realtime and (mem_bytes == 0 or maxmem_bytes == 0 or cpu_pct == 0.0)

        if should_fetch_rrd:
            rrd_cpu, rrd_mem, rrd_max = self._rrd_last(node, vmid_int)
            if (cpu_pct is None or cpu_pct == 0.0) and rrd_cpu is not None:
                cpu_pct = rrd_cpu
            if (mem_bytes is None or mem_bytes == 0) and rrd_mem is not None:
                mem_bytes = rrd_mem
            if (maxmem_bytes is None or maxmem_bytes == 0) and rrd_max:
                maxmem_bytes = rrd_max
                if mem_mib == 0:
                    try:
                        mem_mib = int(round(rrd_max / (1024 * 1024)))
                    except (TypeError, ValueError):
                        pass

        rec["cores"] = cores
        rec["memory_mib"] = mem_mib
        rec["cpu_pct"] = cpu_pct
        rec["mem_bytes"] = mem_bytes
        rec["maxmem_bytes"] = maxmem_bytes
        rec["mem_pct"] = _round(mem_bytes / maxmem_bytes * 100.0) if maxmem_bytes > 0 else None
        rec["unlimited_memory"] = unlimited
        rec["restricted"] = (
            self._add_restricted_flag(str(vmid_raw)) if vmid_raw is not None else False
        )
        return rec

    # -- public API --

    @px_error
    def get_containers(
        self,
        node: Optional[str] = None,
        include_stats: bool = True,
        realtime: bool = False,
    ) -> List[Dict]:
        """List containers using cluster resources for speed, falling back to per-node if needed."""
        try:
            # Use cluster resources for bulk fetch (1 API call instead of 2N+1)
            resources = _as_list(self.px.cluster.resources.get(type="lxc"))
            if node:
                resources = [r for r in resources if _get(r, "node") == node]

            if not include_stats:
                return [
                    {
                        "vmid": str(_get(r, "vmid")),
                        "name": _get(r, "name") or f"ct-{_get(r, 'vmid')}",
                        "node": _get(r, "node"),
                        "status": _get(r, "status"),
                        "restricted": self._add_restricted_flag(str(_get(r, "vmid"))),
                    }
                    for r in resources
                ]

            # If stats requested, we still use the bulk data as much as possible
            results = []
            for r in resources:
                vmid = _get(r, "vmid")
                nname = _get(r, "node")

                rec = {
                    "vmid": str(vmid),
                    "name": _get(r, "name") or f"ct-{vmid}",
                    "node": nname,
                    "status": _get(r, "status"),
                    "cores": _get(r, "maxcpu"),
                    "memory_mib": int(_get(r, "maxmem", 0) / (1024 * 1024))
                    if _get(r, "maxmem")
                    else 0,
                    "cpu_pct": _round(float(_get(r, "cpu", 0) or 0) * 100.0),
                    "mem_bytes": _get(r, "mem", 0),
                    "maxmem_bytes": _get(r, "maxmem", 0),
                    "mem_pct": _round(_get(r, "mem", 0) / _get(r, "maxmem", 1) * 100.0)
                    if _get(r, "maxmem")
                    else 0,
                    "restricted": self._add_restricted_flag(str(vmid)),
                }

                # Only drill down if realtime or missing critical info
                if realtime:
                    raw_s, _ = self._status_config(nname, int(vmid))
                    rec["cpu_pct"] = _round(float(_get(raw_s, "cpu", 0) or 0) * 100.0)
                    rec["mem_bytes"] = int(_get(raw_s, "mem", 0) or 0)

                results.append(rec)
            return results

        except Exception:
            # Cluster resources API unavailable (e.g. single-node without cluster config); fall back to per-node enumeration
            pairs = self._list_pairs(node)
            return [self._flatten_ct(n, ct, include_stats, realtime) for n, ct in pairs]

    @px_op
    def start_container(
        self,
        selector: str | int | List[str | int],
        wait: bool = True,
        timeout_s: int = 60,
        retry: bool = True,
    ) -> Dict[str, Any] | List[Dict[str, Any]]:
        return self._batch_action(
            selector,
            action=lambda n, v: str(self.px.nodes(n).lxc(v).status.start.post()),
            wait=wait,
            retry=retry,
            timeout_s=timeout_s,
        )

    @px_op
    def stop_container(
        self,
        selector: str | int | List[str | int],
        graceful: bool = True,
        grace_timeout_s: int = 10,
        wait: bool = True,
        timeout_s: int = 60,
        retry: bool = True,
    ) -> Dict[str, Any] | List[Dict[str, Any]]:
        return self._batch_action(
            selector,
            action=lambda n, v: (
                str(self.px.nodes(n).lxc(v).status.shutdown.post(timeout=grace_timeout_s))
                if graceful
                else str(self.px.nodes(n).lxc(v).status.stop.post())
            ),
            wait=wait,
            retry=retry,
            timeout_s=timeout_s,
        )

    @px_op
    def restart_container(
        self,
        selector: str | int | List[str | int],
        wait: bool = True,
        timeout_s: int = 60,
        retry: bool = True,
    ) -> Dict[str, Any] | List[Dict[str, Any]]:
        return self._batch_action(
            selector,
            action=lambda n, v: str(self.px.nodes(n).lxc(v).status.reboot.post()),
            wait=wait,
            retry=retry,
            timeout_s=timeout_s,
        )

    @px_error
    def execute_command(
        self, selector: str | int | List[str | int], command: str, timeout: int = 60
    ) -> Dict[str, Any]:
        """Execute a shell command inside a container. Returns
        {"success": bool, "output": str, "error": str, "exit_code": int}."""
        if self.exec_ is None:
            return {
                "error": True,
                "reason": "SSH not configured. Add ssh section to config.json with user/key_file.",
                "fix": "Set PROXMOX_CONFIG or create ~/.config/proxmox/config.json with ssh block.",
            }
        targets = self._resolve(selector)
        if not targets:
            return {
                "error": True,
                "reason": f"No container matched selector: {selector}",
            }
        if len(targets) > 1:
            return {
                "error": True,
                "reason": f"Selector '{selector}' matched {len(targets)} containers; must match exactly one.",
                "fix": "Use node:vmid or a unique name to select a single container.",
            }
        node, vmid, label = targets[0]
        return self.exec_.run(node, str(vmid), command, timeout=timeout)

    @px_error
    def wait_until(
        self,
        selector: str | int | List[str | int],
        command: str,
        timeout_s: int = 300,
        interval_s: int = 5,
    ) -> Dict[str, Any]:
        """Poll command inside container until exit 0 or timeout."""
        if self.exec_ is None:
            return {
                "error": True,
                "reason": "SSH not configured.",
                "fix": "Add ssh section to config.",
            }
        targets = self._resolve(selector)
        if not targets:
            return {
                "error": True,
                "reason": f"No container matched selector: {selector}",
            }
        node, vmid, label = targets[0]
        return self.exec_.wait_until(node, str(vmid), command, timeout_s, interval_s)

    @px_error
    def get_container_config(self, node: str, vmid: str) -> Dict[str, Any]:
        config = _as_dict(self.px.nodes(node).lxc(vmid).config.get())
        config.pop("description", None)
        config.pop("digest", None)
        config.pop("lock", None)
        config.setdefault("vmid", str(vmid))
        return config

    @px_error
    def get_container_ip(self, node: str, vmid: str) -> Dict[str, Any]:
        interfaces_raw = _as_list(self.px.nodes(node).lxc(vmid).interfaces.get())
        config = _as_dict(self.px.nodes(node).lxc(vmid).config.get())
        name = _get(config, "hostname") or f"ct-{vmid}"
        interfaces: List[Dict] = []
        primary_ip: Optional[str] = None
        for iface in interfaces_raw:
            iface_name = _get(iface, "name") or _get(iface, "iface")
            if iface_name == "lo":
                continue
            entry: Dict[str, Any] = {"name": iface_name}
            hwaddr = _get(iface, "hwaddr") or _get(iface, "hardware-address")
            if hwaddr:
                entry["hwaddr"] = hwaddr
            # Prefer ip-addresses array (Proxmox >= 8.1), fall back to inet/inet6 strings
            ip_addresses = _get(iface, "ip-addresses")
            if isinstance(ip_addresses, list):
                ipv4_list: List[str] = []
                ipv6_list: List[str] = []
                for addr in ip_addresses:
                    ip = _get(addr, "ip-address")
                    prefix = _get(addr, "prefix")
                    if not ip:
                        continue
                    cidr = f"{ip}/{prefix}" if prefix else ip
                    if _get(addr, "ip-address-type") == "inet":
                        ipv4_list.append(cidr)
                    else:
                        ipv6_list.append(cidr)
                if ipv4_list:
                    entry["inet"] = ", ".join(ipv4_list)
                    if primary_ip is None:
                        primary_ip = ipv4_list[0].split("/")[0]
                if ipv6_list:
                    entry["inet6"] = ", ".join(ipv6_list)
            else:
                inet = _get(iface, "inet")
                inet6 = _get(iface, "inet6")
                if inet:
                    if isinstance(inet, list):
                        entry["inet"] = ", ".join(inet)
                        if primary_ip is None and inet:
                            primary_ip = inet[0].split("/")[0]
                    else:
                        entry["inet"] = inet
                        if primary_ip is None:
                            primary_ip = inet.split("/")[0]
                if inet6:
                    if isinstance(inet6, list):
                        entry["inet6"] = ", ".join(inet6)
                    else:
                        entry["inet6"] = inet6
            interfaces.append(entry)
        return {
            "vmid": str(vmid),
            "name": name,
            "interfaces": interfaces,
            "primary_ip": primary_ip,
        }

    @px_op
    def update_container_resources(
        self,
        selector: str | int | List[str | int],
        cores: Optional[int] = None,
        memory: Optional[int] = None,
        swap: Optional[int] = None,
        disk_gb: Optional[int] = None,
        disk: str = "rootfs",
    ) -> Dict[str, Any] | List[Dict[str, Any]]:
        targets = self._resolve(selector)
        if not targets:
            return {
                "error": True,
                "reason": f"No containers matched selector: {selector}",
            }
        results = []
        for node, vmid, label in targets:
            restricted = self._check_restriction(str(vmid), label, node)
            if restricted:
                restricted["success"] = False
                results.append(restricted)
                continue
            rec: Dict[str, Any] = {
                "success": True,
                "node": node,
                "vmid": vmid,
                "name": label,
            }
            changes: List[str] = []
            try:
                params: Dict[str, Any] = {}
                if cores is not None:
                    params["cores"] = cores
                    changes.append(f"cores={cores}")
                if memory is not None:
                    params["memory"] = memory
                    changes.append(f"memory={memory}MiB")
                if swap is not None:
                    params["swap"] = swap
                    changes.append(f"swap={swap}MiB")
                if params:
                    self.px.nodes(node).lxc(vmid).config.put(**params)
                if disk_gb is not None:
                    self.px.nodes(node).lxc(vmid).resize.put(disk=disk, size=f"+{disk_gb}G")
                    changes.append(f"{disk}+={disk_gb}G")
                rec["changes"] = changes
            except Exception as e:
                rec["success"] = False
                rec["error"] = str(e)
            results.append(rec)
        return results

    @px_op
    def update_container_ssh_keys(
        self, node: str, vmid: str, public_keys: str, mode: str = "append"
    ) -> Dict[str, Any]:
        if self.exec_ is None:
            return {
                "error": True,
                "reason": "SSH not configured.",
                "fix": "Add ssh section to config with user/key_file.",
            }
        keys = [k.strip() for k in public_keys.strip().splitlines() if k.strip()]
        if not keys:
            return {
                "error": True,
                "reason": "public_keys must contain at least one key",
                "fix": "Pass one or more SSH public keys separated by newlines.",
            }
        mkdir = self.exec_.run(node, str(vmid), "mkdir -p /root/.ssh && chmod 700 /root/.ssh")
        if not mkdir.get("success"):
            return {
                "error": True,
                "reason": f"mkdir /root/.ssh failed: {mkdir.get('output')}",
            }
        joined = "\n".join(keys)
        escaped = joined.replace("'", "'\\''")
        redirect = ">" if mode == "replace" else ">>"
        cmd = f"printf '%s\\n' '{escaped}' {redirect} /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"
        write = self.exec_.run(node, str(vmid), cmd)
        if not write.get("success"):
            return {"error": True, "reason": f"Key write failed: {write.get('output')}"}
        return {"success": True, "keys_added": len(keys)}

    @px_op
    def create_container(
        self,
        node: str,
        vmid: str,
        ostemplate: str,
        hostname: Optional[str] = None,
        cores: int = 1,
        memory: int = 512,
        swap: int = 512,
        disk_size: int = 8,
        storage: Optional[str] = None,
        password: Optional[str] = None,
        ssh_public_keys: Optional[str] = None,
        network_bridge: str = "vmbr0",
        start_after_create: bool = False,
        unprivileged: bool = True,
        wait: bool = True,
        timeout_s: int = 300,
        retry: bool = True,
    ) -> Dict[str, Any]:
        new_check = self._check_restriction("new", "create_container", node)
        if new_check:
            new_check["success"] = False
            return new_check
        conflict = _check_vmid_free(self.px, vmid)
        if conflict:
            return conflict
        nodes_raw = _as_list(self.px.nodes.get())
        node_names = [_get(n, "node") for n in nodes_raw]
        if node not in node_names:
            return {
                "error": True,
                "reason": f"Node '{node}' not found",
                "fix": f"Available nodes: {', '.join(node_names)}",
            }
        if not storage:
            node_storages = _as_list(self.px.nodes(node).storage.get())
            for s in node_storages:
                name = _get(s, "storage")
                if name.startswith("local-") and "rootdir" in _get(s, "content", ""):
                    storage = name
                    break
            if not storage:
                for s in node_storages:
                    if "rootdir" in _get(s, "content", ""):
                        storage = _get(s, "storage")
                        break
        if not storage:
            return {
                "error": True,
                "reason": "No storage found for container rootfs",
                "fix": "Create a storage pool supporting 'rootdir' type.",
            }
        if not hostname:
            hostname = f"ct-{vmid}"
        params: Dict[str, Any] = {
            "vmid": int(vmid),
            "ostemplate": ostemplate,
            "hostname": hostname,
            "cores": cores,
            "memory": memory,
            "swap": swap,
            "rootfs": f"{storage}:{disk_size}",
            "net0": f"name=eth0,bridge={network_bridge},ip=dhcp",
            "unprivileged": 1 if unprivileged else 0,
            "start": 1 if start_after_create else 0,
        }
        if password:
            params["password"] = password
        if ssh_public_keys:
            params["ssh-public-keys"] = ssh_public_keys
        r = _run_with_retry(
            self.px,
            node,
            lambda: str(self.px.nodes(node).lxc.create(**params)),
            wait=wait,
            retry=retry,
            timeout_s=timeout_s,
        )
        base = {
            "vmid": str(vmid),
            "hostname": hostname,
            "node": node,
            "ostemplate": ostemplate,
            "cores": cores,
            "memory_mib": memory,
            "swap_mib": swap,
            "disk_gb": disk_size,
            "storage": storage,
            "network_bridge": network_bridge,
            "unprivileged": unprivileged,
            "start_after_create": start_after_create,
        }
        if wait:
            base["success"] = r.get("success", False)
            base["output"] = r.get("output", "")
            base["elapsed"] = r.get("elapsed", 0)
            if base["success"]:
                self._store_ownership_hash(node, vmid, "lxc")
        else:
            base["task"] = r if isinstance(r, str) else ""
        return base

    @px_op
    def delete_container(
        self,
        selector: str | int | List[str | int],
        force: bool = False,
        wait: bool = True,
        timeout_s: int = 60,
        retry: bool = True,
    ) -> Dict[str, Any] | List[Dict[str, Any]]:
        targets = self._resolve(selector)
        if not targets:
            return {
                "error": True,
                "reason": f"No containers matched selector: {selector}",
            }
        results = []
        for node, vmid, label in targets:
            restricted = self._check_restriction(str(vmid), label, node)
            if restricted:
                restricted["success"] = False
                results.append(restricted)
                continue
            rec: Dict[str, Any] = {
                "success": True,
                "node": node,
                "vmid": vmid,
                "name": label,
            }
            try:
                sd = _as_dict(self.px.nodes(node).lxc(vmid).status.current.get())
                cur = _get(sd, "status", "").lower()
                if cur == "running":
                    if not force:
                        rec["success"] = False
                        rec["error"] = "Container is running. Use force=True to stop and delete."
                        results.append(rec)
                        continue
                    stop_upid = str(self.px.nodes(node).lxc(vmid).status.stop.post())
                    stop_r = _wait_task(self.px, node, stop_upid, timeout_s // 2)
                    if not stop_r.get("success"):
                        rec["success"] = False
                        rec["output"] = f"Stop failed: {stop_r.get('output', '')}"
                        rec["elapsed"] = stop_r.get("elapsed", 0)
                        results.append(rec)
                        continue
                    stop_elapsed = stop_r.get("elapsed", 0)
                    rec["message"] = "Stopped and deleted"
                else:
                    stop_elapsed = 0
                    rec["message"] = "Deleted"
                delete_timeout = max(1, timeout_s - int(stop_elapsed))
                task = self.px.nodes(node).lxc(vmid).delete()
                upid = str(task)
                if wait:
                    r = _wait_task(self.px, node, upid, delete_timeout)
                    rec["success"] = r.get("success", False)
                    rec["output"] = r.get("output", "")
                    rec["elapsed"] = r.get("elapsed", 0)
                    if rec["success"]:
                        self.owned_hashes.pop(str(vmid), None)
                else:
                    rec["task"] = upid
            except Exception as e:
                rec["success"] = False
                rec["error"] = str(e)
            results.append(rec)
        return results


# ---------------------------------------------------------------------------
# 9. NodeTools
# ---------------------------------------------------------------------------


class NodeTools:
    """Proxmox node operations — returns native dicts/lists."""

    def __init__(
        self,
        proxmox_api: Any,
        server_cfg: Optional[Dict[str, Any]] = None,
        owned_hashes: Optional[Dict[str, str]] = None,
    ) -> None:
        self.px = proxmox_api
        self.server_cfg = server_cfg or {}
        self.owned_hashes = owned_hashes if owned_hashes is not None else {}

    def _add_restricted_flag(self, identifier: str) -> bool:
        return _add_restricted_flag(identifier, self.server_cfg, self.owned_hashes)

    @px_error
    def get_nodes(self) -> List[Dict]:
        raw = _as_list(self.px.nodes.get())
        nodes = []
        for n in raw:
            name = _get(n, "node")
            if not name:
                continue
            rec: Dict[str, Any] = {
                "node": name,
                "status": _get(n, "status"),
                "uptime": _get(n, "uptime", 0),
                "cpu_cores": _get(n, "maxcpu"),
                "cpu_pct": _round(float(_get(n, "cpu", 0) or 0) * 100.0),
                "mem_used": _get(n, "mem", 0),
                "mem_total": _get(n, "maxmem", 0),
                "mem_pct": _round(_get(n, "mem", 0) / _get(n, "maxmem", 1) * 100.0)
                if _get(n, "maxmem")
                else None,
                "disk_used": _get(n, "diskused", 0),
                "disk_total": _get(n, "maxdisk", 0),
                "restricted": self._add_restricted_flag(name),
            }
            nodes.append(rec)
        return nodes

    @px_error
    def get_node_status(self, node: str) -> Dict[str, Any]:
        try:
            result = _as_dict(self.px.nodes(node).status.get())
        except Exception as e:
            nodes = _as_list(self.px.nodes.get())
            for entry in nodes:
                if _get(entry, "node") == node and _get(entry, "status") == "offline":
                    return {
                        "node": node,
                        "status": "offline",
                        "uptime": 0,
                        "cpu_cores": None,
                        "cpu_pct": 0.0,
                        "mem_used": _get(entry, "mem", 0),
                        "mem_total": _get(entry, "maxmem", 0),
                    }
            raise e
        mem = _as_dict(_get(result, "memory"))
        cpuinfo = _as_dict(_get(result, "cpuinfo"))
        return {
            "node": node,
            "status": _get(result, "status") or "online",
            "uptime": _get(result, "uptime", 0),
            "cpu_cores": _get(cpuinfo, "cpus"),
            "cpu_pct": _round(float(_get(result, "cpu", 0) or 0) * 100.0),
            "mem_used": _get(mem, "used", 0),
            "mem_total": _get(mem, "total", 0),
            "mem_pct": _round(_get(mem, "used", 0) / _get(mem, "total", 1) * 100.0)
            if _get(mem, "total")
            else None,
            "kversion": _get(result, "kversion"),
            "pveversion": _get(result, "pveversion"),
        }


# ---------------------------------------------------------------------------
# 10. VMTools
# ---------------------------------------------------------------------------


class VMTools(_BaseTools):
    """Proxmox VM (QEMU) operations — returns native dicts/lists."""

    _target_type = "VMs"
    _resource_type = "qemu"

    def __init__(
        self,
        proxmox_api: Any,
        server_cfg: Optional[Dict[str, Any]] = None,
        owned_hashes: Optional[Dict[str, str]] = None,
    ) -> None:
        super().__init__(proxmox_api, server_cfg=server_cfg, owned_hashes=owned_hashes)

    def _vm_status(self, node: str, vmid: int) -> str:
        """Return the current status string for a VM (e.g. 'running', 'stopped')."""
        return _get(_as_dict(self.px.nodes(node).qemu(vmid).status.current.get()), "status") or ""

    def _vm_stopped_pre_check(self, node: str, vmid: int, label: str) -> Optional[Dict[str, Any]]:
        """Return an already_stopped result if the VM is stopped, else None."""
        if self._vm_status(node, vmid) == "stopped":
            return {
                "vmid": str(vmid),
                "node": node,
                "name": label,
                "status": "already_stopped",
                "success": True,
            }
        return None

    @px_error
    def get_vms(self, node: Optional[str] = None) -> List[Dict]:
        """List VMs using cluster resources for speed."""
        try:
            resources = _as_list(self.px.cluster.resources.get(type="qemu"))
            if node:
                resources = [r for r in resources if _get(r, "node") == node]

            results = []
            for r in resources:
                vmid = str(_get(r, "vmid"))
                results.append(
                    {
                        "vmid": vmid,
                        "name": _get(r, "name"),
                        "status": _get(r, "status"),
                        "node": _get(r, "node"),
                        "cores": _get(r, "maxcpu"),
                        "mem_bytes": _get(r, "mem", 0),
                        "maxmem_bytes": _get(r, "maxmem", 0),
                        "cpu_pct": _round(float(_get(r, "cpu", 0) or 0) * 100.0),
                        "restricted": self._add_restricted_flag(vmid),
                    }
                )
            return results
        except Exception:
            # Cluster resources API unavailable; fall back to per-node enumeration
            pairs = self._list_pairs(node)
            vms: List[Dict] = []
            for name, vm in pairs:
                vmid = _get(vm, "vmid")
                try:
                    cfg = _as_dict(self.px.nodes(name).qemu(vmid).config.get())
                    cores = _get(cfg, "cores")
                except Exception:
                    cores = None  # VM config fetch failed (e.g. transitioning state); omit cores from result
                mem_bytes = _get(vm, "mem", 0)
                maxmem_bytes = _get(vm, "maxmem", 0)
                vms.append(
                    {
                        "vmid": str(vmid),
                        "name": _get(vm, "name"),
                        "status": _get(vm, "status"),
                        "node": name,
                        "cores": cores,
                        "mem_bytes": mem_bytes,
                        "maxmem_bytes": maxmem_bytes,
                        "cpu_pct": _round(float(_get(vm, "cpu", 0) or 0) * 100.0),
                        "restricted": self._add_restricted_flag(str(vmid)),
                    }
                )
            return vms

    @px_op
    def start_vm(
        self,
        selector: str | int | List[str | int],
        wait: bool = True,
        timeout_s: int = 60,
        retry: bool = True,
    ) -> Dict[str, Any] | List[Dict[str, Any]]:
        return self._batch_action(
            selector,
            action=lambda n, v: str(self.px.nodes(n).qemu(v).status.start.post()),
            pre_check=lambda n, v, label: (
                {
                    "vmid": str(v),
                    "node": n,
                    "name": label,
                    "status": "already_running",
                    "success": True,
                }
                if self._vm_status(n, v) == "running"
                else None
            ),
            wait=wait,
            retry=retry,
            timeout_s=timeout_s,
        )

    @px_op
    def stop_vm(
        self,
        selector: str | int | List[str | int],
        wait: bool = True,
        timeout_s: int = 60,
        retry: bool = True,
    ) -> Dict[str, Any] | List[Dict[str, Any]]:
        return self._batch_action(
            selector,
            action=lambda n, v: str(self.px.nodes(n).qemu(v).status.stop.post()),
            pre_check=self._vm_stopped_pre_check,
            wait=wait,
            retry=retry,
            timeout_s=timeout_s,
        )

    @px_op
    def shutdown_vm(
        self,
        selector: str | int | List[str | int],
        wait: bool = True,
        timeout_s: int = 60,
        retry: bool = True,
    ) -> Dict[str, Any] | List[Dict[str, Any]]:
        return self._batch_action(
            selector,
            action=lambda n, v: str(self.px.nodes(n).qemu(v).status.shutdown.post()),
            pre_check=self._vm_stopped_pre_check,
            wait=wait,
            retry=retry,
            timeout_s=timeout_s,
        )

    @px_op
    def reset_vm(
        self,
        selector: str | int | List[str | int],
        wait: bool = True,
        timeout_s: int = 60,
        retry: bool = True,
    ) -> Dict[str, Any] | List[Dict[str, Any]]:
        return self._batch_action(
            selector,
            action=lambda n, v: str(self.px.nodes(n).qemu(v).status.reset.post()),
            pre_check=lambda n, v, label: (
                {
                    "error": True,
                    "node": n,
                    "vmid": str(v),
                    "name": label,
                    "reason": f"VM {v} is stopped. Use start_vm first.",
                    "fix": "Start the VM before resetting.",
                }
                if self._vm_status(n, v) == "stopped"
                else None
            ),
            wait=wait,
            retry=retry,
            timeout_s=timeout_s,
        )

    @px_op
    def restart_vm(
        self,
        selector: str | int | List[str | int],
        wait: bool = True,
        timeout_s: int = 120,
        retry: bool = True,
    ) -> Dict[str, Any] | List[Dict[str, Any]]:
        """Gracefully shutdown then start a VM."""
        targets = self._resolve(selector)
        if not targets:
            return {"error": True, "reason": f"No {self._target_type} matched selector: {selector}"}
        results = []
        for node, vmid, label in targets:
            res: Dict[str, Any] = {"vmid": str(vmid), "node": node, "name": label}
            if self._vm_status(node, vmid) == "stopped":
                start_r = _run_with_retry(
                    self.px,
                    node,
                    lambda n=node, v=vmid: str(self.px.nodes(n).qemu(v).status.start.post()),
                    wait=wait,
                    retry=retry,
                    timeout_s=timeout_s,
                )
                if wait:
                    res["success"] = start_r.get("success", False)
                    res["output"] = start_r.get("output", "")
                    res["elapsed"] = start_r.get("elapsed", 0)
                else:
                    res["status"] = "start_initiated"
                    res["start_task"] = start_r if isinstance(start_r, str) else ""
                results.append(res)
                continue
            shutdown_r = _run_with_retry(
                self.px,
                node,
                lambda n=node, v=vmid: str(self.px.nodes(n).qemu(v).status.shutdown.post()),
                wait=wait,
                retry=retry,
                timeout_s=timeout_s // 2,
            )
            if wait and not shutdown_r.get("success"):
                res["success"] = False
                res["output"] = f"Shutdown failed: {shutdown_r.get('output', '')}"
                res["elapsed"] = shutdown_r.get("elapsed", 0)
                results.append(res)
                continue
            start_r = _run_with_retry(
                self.px,
                node,
                lambda n=node, v=vmid: str(self.px.nodes(n).qemu(v).status.start.post()),
                wait=wait,
                retry=retry,
                timeout_s=timeout_s // 2,
            )
            if wait:
                res["success"] = start_r.get("success", False)
                res["output"] = (
                    f"Shutdown: {shutdown_r.get('output', '')}\nStart: {start_r.get('output', '')}"
                )
                res["elapsed"] = _round(shutdown_r.get("elapsed", 0) + start_r.get("elapsed", 0))
            else:
                res["status"] = "restart_initiated"
                res["shutdown_task"] = shutdown_r if isinstance(shutdown_r, str) else ""
                res["start_task"] = start_r if isinstance(start_r, str) else ""
            results.append(res)
        return results

    @px_op
    def delete_vm(
        self,
        selector: str | int | List[str | int],
        force: bool = False,
        wait: bool = True,
        timeout_s: int = 60,
        retry: bool = True,
    ) -> Dict[str, Any] | List[Dict[str, Any]]:
        targets = self._resolve(selector)
        if not targets:
            return {"error": True, "reason": f"No {self._target_type} matched selector: {selector}"}
        results = []
        for node, vmid, label in targets:
            restricted = self._check_restriction(str(vmid), label, node)
            if restricted:
                restricted["success"] = False
                results.append(restricted)
                continue
            status = _as_dict(self.px.nodes(node).qemu(vmid).status.current.get())
            cur = _get(status, "status")
            name = _get(status, "name") or label
            if cur == "running":
                if not force:
                    results.append(
                        {
                            "error": True,
                            "node": node,
                            "vmid": str(vmid),
                            "name": name,
                            "reason": f"VM {vmid} ({name}) is running. Use force=True to stop and delete.",
                            "fix": "Stop the VM first, or pass force=True.",
                        }
                    )
                    continue
                stop_upid = str(self.px.nodes(node).qemu(vmid).status.stop.post())
                stop_r = _wait_task(self.px, node, stop_upid, timeout_s // 2)
                if not stop_r.get("success"):
                    results.append(
                        {
                            "error": True,
                            "node": node,
                            "vmid": str(vmid),
                            "name": name,
                            "reason": f"Stop failed before delete: {stop_r.get('output', '')}",
                        }
                    )
                    continue
                delete_timeout = max(1, timeout_s - int(stop_r.get("elapsed", 0)))
            else:
                delete_timeout = timeout_s
            r = _run_with_retry(
                self.px,
                node,
                lambda: str(self.px.nodes(node).qemu(vmid).delete()),
                wait=wait,
                retry=retry,
                timeout_s=delete_timeout,
            )
            res = {"vmid": str(vmid), "name": name, "node": node}
            if wait:
                res["success"] = r.get("success", False)
                res["output"] = r.get("output", "")
                res["elapsed"] = r.get("elapsed", 0)
                if res["success"]:
                    self.owned_hashes.pop(str(vmid), None)
            else:
                res["status"] = "deletion_initiated"
                res["task"] = r if isinstance(r, str) else ""
            results.append(res)
        return results

    @px_op
    def create_vm(
        self,
        node: str,
        vmid: str,
        name: str,
        cpus: int,
        memory: int,
        disk_size: int,
        storage: Optional[str] = None,
        ostype: Optional[str] = None,
        network_bridge: Optional[str] = None,
        wait: bool = True,
        timeout_s: int = 120,
        retry: bool = True,
    ) -> Dict[str, Any]:
        new_check = self._check_restriction("new", "create_vm", node)
        if new_check:
            new_check["success"] = False
            return new_check
        conflict = _check_vmid_free(self.px, vmid)
        if conflict:
            return conflict
        node_storages = _as_list(self.px.nodes(node).storage.get())
        if not storage:
            for s in node_storages:
                name = _get(s, "storage")
                if name.startswith("local-") and "images" in _get(s, "content", ""):
                    storage = name
                    break
            if not storage:
                for s in node_storages:
                    if "images" in _get(s, "content", ""):
                        storage = _get(s, "storage")
                        break
        if not storage:
            return {
                "error": True,
                "reason": "No storage found for VM images",
                "fix": "Create a storage pool supporting 'images' type.",
            }
        storages = {_get(s, "storage"): s for s in node_storages}
        stype = _get(storages.get(storage, {}), "type", "raw")
        if stype in ("lvm", "lvmthin"):
            disk_str = f"{storage}:{disk_size},format=raw"
        elif stype in ("dir", "nfs", "cifs"):
            disk_str = f"{storage}:{disk_size},format=qcow2"
        else:
            disk_str = f"{storage}:{disk_size},format=raw"
        net = network_bridge or "vmbr0"
        params: Dict[str, Any] = {
            "vmid": int(vmid),
            "name": name,
            "cores": cpus,
            "memory": memory,
            "ostype": ostype or "l26",
            "scsihw": "virtio-scsi-pci",
            "boot": "order=scsi0",
            "agent": "1",
            "vga": "std",
            "scsi0": disk_str,
            "net0": f"virtio,bridge={net}",
        }
        r = _run_with_retry(
            self.px,
            node,
            lambda: str(self.px.nodes(node).qemu.create(**params)),
            wait=wait,
            retry=retry,
            timeout_s=timeout_s,
        )
        base = {
            "vmid": str(vmid),
            "name": name,
            "node": node,
            "cores": cpus,
            "memory_mib": memory,
            "disk_gb": disk_size,
            "storage": storage,
        }
        if wait:
            base["success"] = r.get("success", False)
            base["output"] = r.get("output", "")
            base["elapsed"] = r.get("elapsed", 0)
            if base["success"]:
                self._store_ownership_hash(node, vmid, "qemu")
        else:
            base["task"] = r if isinstance(r, str) else ""
        return base

    @px_op
    def update_vm_resources(
        self,
        selector: str | int | List[str | int],
        cores: Optional[int] = None,
        memory: Optional[int] = None,
    ) -> Dict[str, Any] | List[Dict[str, Any]]:
        """Hot-resize VM CPU and memory. Returns updated config."""
        targets = self._resolve(selector)
        if not targets:
            return {
                "error": True,
                "reason": f"No VMs matched selector: {selector}",
            }
        results = []
        for node, vmid, label in targets:
            restricted = self._check_restriction(str(vmid), label, node)
            if restricted:
                restricted["success"] = False
                results.append(restricted)
                continue
            params: Dict[str, Any] = {}
            changes: List[str] = []
            if cores is not None:
                params["cores"] = cores
                changes.append(f"cores={cores}")
            if memory is not None:
                params["memory"] = memory
                changes.append(f"memory={memory}MiB")
            if not params:
                results.append(
                    {
                        "error": True,
                        "node": node,
                        "vmid": str(vmid),
                        "name": label,
                        "reason": "No changes specified",
                    }
                )
                continue
            try:
                self.px.nodes(node).qemu(vmid).config.put(**params)
                results.append(
                    {
                        "success": True,
                        "node": node,
                        "vmid": str(vmid),
                        "name": label,
                        "changes": changes,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "error": True,
                        "node": node,
                        "vmid": str(vmid),
                        "name": label,
                        "reason": str(e),
                        "fix": "Verify VM exists and is running for hot-resize.",
                    }
                )
        return results


# ---------------------------------------------------------------------------
# 11. SnapshotTools
# ---------------------------------------------------------------------------


class SnapshotTools:
    """Snapshot operations for VMs and containers."""

    def __init__(
        self,
        proxmox_api: Any,
        server_cfg: Optional[Dict[str, Any]] = None,
        owned_hashes: Optional[Dict[str, str]] = None,
    ) -> None:
        self.px = proxmox_api
        self.server_cfg = server_cfg or {}
        self.owned_hashes = owned_hashes if owned_hashes is not None else {}

    def _check_restriction(
        self, identifier: str, label: str, node: Optional[str] = None, vmid: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        return _check_access(identifier, label, self.server_cfg, self.owned_hashes, node, vmid)

    def _endpoint(self, node: str, vmid: str, vm_type: str):
        if vm_type == "lxc":
            return self.px.nodes(node).lxc(vmid).snapshot
        return self.px.nodes(node).qemu(vmid).snapshot

    @px_error
    def list_snapshots(self, node: str, vmid: str, vm_type: str = "qemu") -> List[Dict]:
        snaps = _as_list(self._endpoint(node, vmid, vm_type).get())
        result = []
        for s in snaps:
            name = _get(s, "name")
            if name == "current":
                continue
            rec: Dict[str, Any] = {"name": name, "parent": _get(s, "parent", "")}
            snaptime = _get(s, "snaptime")
            if snaptime:
                try:
                    rec["created"] = datetime.fromtimestamp(snaptime).strftime("%Y-%m-%d %H:%M:%S")
                except (OSError, OverflowError, ValueError):
                    rec["created"] = str(snaptime)
            if _get(s, "vmstate"):
                rec["ram_included"] = True
            result.append(rec)
        return result

    @px_op
    def create_snapshot(
        self,
        node: str,
        vmid: str,
        snapname: str,
        description: Optional[str] = None,
        vmstate: bool = False,
        vm_type: str = "qemu",
        wait: bool = True,
        timeout_s: int = 60,
        retry: bool = True,
    ) -> Dict[str, Any]:
        restricted = self._check_restriction(vmid, f"{vm_type}:{vmid}", node)
        if restricted:
            restricted["success"] = False
            return restricted
        params: Dict[str, str | int] = {"snapname": snapname}
        if description:
            params["description"] = description
        if vmstate and vm_type == "qemu":
            params["vmstate"] = 1
        ep = self._endpoint
        r = _run_with_retry(
            self.px,
            node,
            lambda: str(ep(node, vmid, vm_type).post(**params)),
            wait=wait,
            retry=retry,
            timeout_s=timeout_s,
        )
        base = {"snapname": snapname, "vmid": str(vmid), "node": node, "vm_type": vm_type}
        if wait:
            base["success"] = r.get("success", False)
            base["output"] = r.get("output", "")
            base["elapsed"] = r.get("elapsed", 0)
        else:
            base["task"] = r if isinstance(r, str) else ""
        return base

    @px_op
    def delete_snapshot(
        self,
        node: str,
        vmid: str,
        snapname: str,
        vm_type: str = "qemu",
        wait: bool = True,
        timeout_s: int = 60,
        retry: bool = True,
    ) -> Dict[str, Any]:
        restricted = self._check_restriction(vmid, f"{vm_type}:{vmid}", node)
        if restricted:
            restricted["success"] = False
            return restricted
        ep = self._endpoint
        r = _run_with_retry(
            self.px,
            node,
            lambda: str(ep(node, vmid, vm_type)(snapname).delete()),
            wait=wait,
            retry=retry,
            timeout_s=timeout_s,
        )
        base = {"snapname": snapname, "vmid": str(vmid), "node": node, "vm_type": vm_type}
        if wait:
            base["success"] = r.get("success", False)
            base["output"] = r.get("output", "")
            base["elapsed"] = r.get("elapsed", 0)
        else:
            base["task"] = r if isinstance(r, str) else ""
        return base

    @px_op
    def rollback_snapshot(
        self,
        node: str,
        vmid: str,
        snapname: str,
        vm_type: str = "qemu",
        wait: bool = True,
        timeout_s: int = 60,
        retry: bool = True,
    ) -> Dict[str, Any]:
        restricted = self._check_restriction(vmid, f"{vm_type}:{vmid}", node)
        if restricted:
            restricted["success"] = False
            return restricted
        endpoint = self._endpoint(node, vmid, vm_type)
        snaps = _as_list(endpoint.get())
        deleted: List[str] = []
        for s in snaps:
            sname = _get(s, "name")
            sparent = _get(s, "parent", "")
            if sname and sname != "current" and sparent == snapname:
                try:
                    endpoint(sname).delete()
                    deleted.append(sname)
                except Exception:
                    pass  # Newer snapshot may already be gone; continue with rollback
        ep = self._endpoint
        r = _run_with_retry(
            self.px,
            node,
            lambda: str(ep(node, vmid, vm_type)(snapname).rollback.post()),
            wait=wait,
            retry=retry,
            timeout_s=timeout_s,
        )
        base = {
            "snapname": snapname,
            "vmid": str(vmid),
            "node": node,
            "vm_type": vm_type,
            "deleted_newer": deleted,
        }
        if wait:
            base["success"] = r.get("success", False)
            base["output"] = r.get("output", "")
            base["elapsed"] = r.get("elapsed", 0)
        else:
            base["task"] = r if isinstance(r, str) else ""
        return base


# ---------------------------------------------------------------------------
# 12. BackupTools
# ---------------------------------------------------------------------------


class BackupTools:
    """Backup and restore operations."""

    def __init__(
        self,
        proxmox_api: Any,
        server_cfg: Optional[Dict[str, Any]] = None,
        owned_hashes: Optional[Dict[str, str]] = None,
    ) -> None:
        self.px = proxmox_api
        self.server_cfg = server_cfg or {}
        self.owned_hashes = owned_hashes if owned_hashes is not None else {}

    def _check_restriction(
        self, identifier: str, label: str, node: Optional[str] = None, vmid: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        return _check_access(identifier, label, self.server_cfg, self.owned_hashes, node, vmid)

    @px_error
    def list_backups(
        self,
        node: Optional[str] = None,
        storage: Optional[str] = None,
        vmid: Optional[str] = None,
    ) -> List[Dict]:
        results: List[Dict] = []
        nodes = _as_list(self.px.nodes.get())
        for n in nodes:
            nname = _get(n, "node")
            if not nname:
                continue
            if node and nname != node:
                continue
            try:
                storages = _as_list(self.px.nodes(nname).storage.get())
            except Exception:
                continue  # Node may be offline; skip and check remaining nodes
            for s in storages:
                sname = _get(s, "storage")
                if not sname:
                    continue
                if storage and sname != storage:
                    continue
                if "backup" not in _get(s, "content", ""):
                    continue
                try:
                    params: Dict[str, str | int] = {"content": "backup"}
                    if vmid:
                        params["vmid"] = int(vmid)
                    content = _as_list(self.px.nodes(nname).storage(sname).content.get(**params))
                    for item in content:
                        ctime = _get(item, "ctime")
                        ts = ""
                        if ctime:
                            try:
                                ts = datetime.fromtimestamp(ctime).strftime("%Y-%m-%d %H:%M:%S")
                            except (OSError, OverflowError, ValueError):
                                ts = str(ctime)
                        results.append(
                            {
                                "volid": _get(item, "volid"),
                                "size": _get(item, "size", 0),
                                "size_human": _b2h(_get(item, "size", 0)),
                                "vmid": _get(item, "vmid"),
                                "format": _get(item, "format"),
                                "ctime": ts,
                                "node": nname,
                                "storage": sname,
                                "protected": bool(_get(item, "protected", False)),
                            }
                        )
                except Exception:
                    continue  # Storage content query may fail (permissions, unavailable); skip this storage
        # Deduplicate: same physical file can appear under multiple storages
        # that share a directory. Identify by the filename portion of the volid.
        seen: Dict[str, int] = {}
        deduped: List[Dict] = []
        for item in results:
            volid = _get(item, "volid", "")
            fname = volid.split(":", 1)[-1] if ":" in volid else volid
            if fname in seen:
                idx = seen[fname]
                deduped[idx].setdefault("also_on", []).append(item["storage"])
            else:
                seen[fname] = len(deduped)
                deduped.append(item)
        deduped.sort(key=lambda x: _get(x, "volid", ""), reverse=True)
        return deduped

    @px_op
    def create_backup(
        self,
        node: str,
        vmid: str,
        storage: str,
        compress: str = "zstd",
        mode: str = "snapshot",
        notes: Optional[str] = None,
        wait: bool = True,
        timeout_s: int = 300,
        retry: bool = True,
    ) -> Dict[str, Any]:
        restricted = self._check_restriction(vmid, f"backup:{vmid}", node)
        if restricted:
            restricted["success"] = False
            return restricted
        params: Dict[str, str] = {
            "vmid": str(vmid),
            "storage": storage,
            "compress": compress,
            "mode": mode,
        }
        if notes:
            params["notes-template"] = notes
        r = _run_with_retry(
            self.px,
            node,
            lambda: str(self.px.nodes(node).vzdump.post(**params)),
            wait=wait,
            retry=retry,
            timeout_s=timeout_s,
        )
        base = {
            "vmid": str(vmid),
            "node": node,
            "storage": storage,
            "compress": compress,
            "mode": mode,
        }
        if wait:
            base["success"] = r.get("success", False)
            base["output"] = r.get("output", "")
            base["elapsed"] = r.get("elapsed", 0)
        else:
            base["task"] = r if isinstance(r, str) else ""
        return base

    @px_op
    def restore_backup(
        self,
        node: str,
        archive: str,
        vmid: str,
        storage: Optional[str] = None,
        unique: bool = True,
        wait: bool = True,
        timeout_s: int = 300,
        retry: bool = True,
    ) -> Dict[str, Any]:
        new_check = self._check_restriction("new", "restore", node)
        if new_check:
            new_check["success"] = False
            return new_check
        restricted = self._check_restriction(vmid, f"restore:{vmid}", node)
        if restricted:
            restricted["success"] = False
            return restricted
        is_lxc = "/ct/" in archive.lower() or "vzdump-lxc" in archive.lower()
        if is_lxc:
            params: Dict[str, str | int] = {"ostemplate": archive, "vmid": int(vmid), "restore": 1}
        else:
            params = {"archive": archive, "vmid": int(vmid)}
        if storage:
            params["storage"] = storage
        if unique:
            params["unique"] = 1

        def _do():
            if is_lxc:
                return str(self.px.nodes(node).lxc.post(**params))
            return str(self.px.nodes(node).qemu.post(**params))

        r = _run_with_retry(self.px, node, _do, wait=wait, retry=retry, timeout_s=timeout_s)
        base = {
            "vmid": str(vmid),
            "node": node,
            "archive": archive,
            "type": "lxc" if is_lxc else "qemu",
        }
        if wait:
            base["success"] = r.get("success", False)
            base["output"] = r.get("output", "")
            base["elapsed"] = r.get("elapsed", 0)
            if base["success"]:
                resource_type = "lxc" if is_lxc else "qemu"
                self._store_ownership_hash(node, vmid, resource_type)
        else:
            base["task"] = r if isinstance(r, str) else ""
        return base

    def _resolve_backup_volid(self, node: str, volid: str) -> Dict[str, Any]:
        """Resolve a possibly-ambiguous volid to a canonical {volid, storage, vmid} or {error}.

        Accepts:
          - Fully qualified:  "local:backup/vzdump-qemu-101-....vma.zst"
          - Storage-prefixed: "local:vzdump-qemu-101-....vma.zst"
          - Bare filename:    "vzdump-qemu-101-....vma.zst"
          - Partial match:    "101-2026_03_25" (must resolve to exactly one backup)
        """

        def _extract_vmid(v: str) -> str:
            fname = v.split(":", 1)[-1] if ":" in v else v
            parts = fname.split("-")
            if len(parts) >= 3 and parts[0] == "vzdump" and parts[1] in ("lxc", "qemu"):
                return parts[2]
            return ""

        needle = volid.strip()

        # If it looks fully-qualified (storage:path), trust it directly
        if ":" in needle:
            storage = needle.split(":", 1)[0]
            return {"volid": needle, "storage": storage, "vmid": _extract_vmid(needle)}

        # Otherwise search all backup storages for a filename match
        matches: List[Dict[str, str]] = []
        for s in _as_list(self.px.nodes(node).storage.get()):
            sname = _get(s, "storage")
            if not sname or "backup" not in _get(s, "content", ""):
                continue
            try:
                for item in _as_list(
                    self.px.nodes(node).storage(sname).content.get(content="backup")
                ):
                    item_volid = _get(item, "volid", "")
                    fname = item_volid.split(":", 1)[-1] if ":" in item_volid else item_volid
                    if needle in fname or needle in item_volid:
                        matches.append(
                            {
                                "volid": item_volid,
                                "storage": sname,
                                "vmid": _extract_vmid(item_volid),
                            }
                        )
            except Exception:
                continue  # Storage unavailable during search; skip and check remaining

        if len(matches) == 1:
            return matches[0]
        if len(matches) == 0:
            return {
                "error": True,
                "reason": f"No backup found matching '{volid}'",
                "fix": "Check bt.list_backups() for valid volids.",
            }
        return {
            "error": True,
            "reason": f"'{volid}' matches {len(matches)} backups — be more specific.",
            "matches": [m["volid"] for m in matches],
            "fix": "Pass a more specific volid or the fully-qualified 'storage:path' form.",
        }

    @px_op
    def delete_backup(
        self,
        node: str,
        volid: str,
        wait: bool = True,
        timeout_s: int = 60,
        retry: bool = True,
    ) -> Dict[str, Any]:
        resolved = self._resolve_backup_volid(node, volid)
        if resolved.get("error"):
            return resolved
        actual_volid: str = resolved["volid"]
        actual_storage: str = resolved["storage"]
        backup_vmid = resolved.get("vmid", "")
        if backup_vmid:
            restricted = self._check_restriction(backup_vmid, f"backup:{backup_vmid}", node)
            if restricted:
                restricted["success"] = False
                return restricted

        content = _as_list(
            self.px.nodes(node).storage(actual_storage).content.get(content="backup")
        )
        for item in content:
            if _get(item, "volid") == actual_volid and _get(item, "protected"):
                return {
                    "error": True,
                    "reason": f"Backup '{actual_volid}' is protected.",
                    "fix": "Remove protection first if you want to delete it.",
                }
        r = _run_with_retry(
            self.px,
            node,
            lambda: str(self.px.nodes(node).storage(actual_storage).content(actual_volid).delete()),
            wait=wait,
            retry=retry,
            timeout_s=timeout_s,
        )
        base: Dict[str, Any] = {"volid": actual_volid, "node": node, "storage": actual_storage}
        if wait:
            base["success"] = r.get("success", False)
            base["output"] = r.get("output", "")
            base["elapsed"] = r.get("elapsed", 0)
            base["deleted"] = r.get("success", False)
        else:
            base["task"] = r if isinstance(r, str) else ""
        # Clean up duplicate references on other storages sharing the same directory
        if wait and base["deleted"]:
            fname = actual_volid.split(":", 1)[-1]
            cleaned: List[str] = []
            for s in _as_list(self.px.nodes(node).storage.get()):
                sname = _get(s, "storage")
                if not sname or sname == actual_storage or "backup" not in _get(s, "content", ""):
                    continue
                try:
                    scontent = _as_list(
                        self.px.nodes(node).storage(sname).content.get(content="backup")
                    )
                    for item in scontent:
                        svolid = _get(item, "volid", "")
                        if svolid.split(":", 1)[-1] == fname:
                            self.px.nodes(node).storage(sname).content(svolid).delete()
                            cleaned.append(sname)
                except Exception:
                    continue  # Mirror copy may already be gone or storage unavailable; skip
            if cleaned:
                base["also_cleaned"] = cleaned
        return base


# ---------------------------------------------------------------------------
# 13. Initialization and exports
# ---------------------------------------------------------------------------

cfg = _load_config()

# Late import: proxmoxer is only available after uv installs it as a dependency.
# cfg = _load_config() above runs at import time and must succeed before the API client is needed.
from proxmoxer import ProxmoxAPI  # noqa: E402


def _connect(c: Config) -> ProxmoxAPI:
    return ProxmoxAPI(
        c.proxmox.get("host"),
        user=c.auth.get("user"),
        token_name=c.auth.get("token_name"),
        token_value=c.auth.get("token_value"),
        verify_ssl=c.proxmox.get("verify_ssl", False),
        timeout=(5, 30),  # (connect_timeout, read_timeout) in seconds
    )


class _ServerProxy:
    """Lazy-load a single named server connection on first access."""

    def __init__(self, server_name: Optional[str] = None, config: Optional[Config] = None) -> None:
        self.cfg = config or cfg
        self.server_name = str(server_name or self.cfg.default_server)
        self._connected = False

    def _server_config(self) -> Dict[str, Any]:
        return self.cfg.get_server(self.server_name)

    def _ensure_connection(self) -> None:
        if self._connected:
            return
        server_cfg = self._server_config()
        proxmox_cfg = server_cfg.get("proxmox", {})
        auth_cfg = server_cfg.get("auth", {})
        ssh_cfg = server_cfg.get("ssh")
        allowlist = [str(i) for i in server_cfg.get("allowlist", [])]
        denylist = [str(i) for i in server_cfg.get("denylist", [])]
        if not proxmox_cfg.get("host"):
            raise RuntimeError(
                f"Proxmox server {self.server_name!r} is not configured. "
                "Set PROXMOX_HOST or create config.json.\n"
                "Checked locations:\n  - " + "\n  - ".join(self.cfg.checked_paths)
            )
        connection_cfg = Config(
            {
                "servers": {self.server_name: server_cfg},
                "default_server": self.server_name,
                "proxmox": proxmox_cfg,
                "auth": auth_cfg,
                "ssh": ssh_cfg,
                "allowlist": allowlist,
                "denylist": denylist,
            },
            loaded_from=self.cfg.loaded_from,
            checked_paths=self.cfg.checked_paths,
        )
        self._px = _connect(connection_cfg)
        self._owned_hashes = _load_ownership_hashes(self._px)
        self._ct = ContainerTools(
            self._px, ssh_cfg, server_cfg=server_cfg, owned_hashes=self._owned_hashes
        )
        self._nt = NodeTools(self._px, server_cfg=server_cfg, owned_hashes=self._owned_hashes)
        self._vt = VMTools(self._px, server_cfg=server_cfg, owned_hashes=self._owned_hashes)
        self._st = SnapshotTools(
            self._px, server_cfg=server_cfg, owned_hashes=self._owned_hashes
        )
        self._bt = BackupTools(self._px, server_cfg=server_cfg, owned_hashes=self._owned_hashes)
        self._connected = True
        atexit.register(self._ct.close)

    @property
    def px(self) -> ProxmoxAPI:
        self._ensure_connection()
        return self._px

    @property
    def ct(self) -> ContainerTools:
        self._ensure_connection()
        return self._ct

    @property
    def nt(self) -> NodeTools:
        self._ensure_connection()
        return self._nt

    @property
    def vt(self) -> VMTools:
        self._ensure_connection()
        return self._vt

    @property
    def st(self) -> SnapshotTools:
        self._ensure_connection()
        return self._st

    @property
    def bt(self) -> BackupTools:
        self._ensure_connection()
        return self._bt


class _ServerRegistry:
    """Cache per-server proxies and expose the default one for legacy imports."""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.cfg = config or cfg
        self._proxies: Dict[str, _ServerProxy] = {}

    def server(self, name: Optional[str] = None) -> _ServerProxy:
        server_name = str(name or self.cfg.default_server)
        if server_name not in self._proxies:
            self._proxies[server_name] = _ServerProxy(server_name, self.cfg)
        return self._proxies[server_name]

    @property
    def px(self) -> ProxmoxAPI:
        return self.server().px

    @property
    def ct(self) -> ContainerTools:
        return self.server().ct

    @property
    def nt(self) -> NodeTools:
        return self.server().nt

    @property
    def vt(self) -> VMTools:
        return self.server().vt

    @property
    def st(self) -> SnapshotTools:
        return self.server().st

    @property
    def bt(self) -> BackupTools:
        return self.server().bt


def server(name: Optional[str] = None) -> _ServerProxy:
    return _pxas.server(name)


_pxas = _ServerRegistry()


def __getattr__(name: str):
    if name == "px":
        return _pxas.px
    if name == "ct":
        return _pxas.ct
    if name == "nt":
        return _pxas.nt
    if name == "vt":
        return _pxas.vt
    if name == "st":
        return _pxas.st
    if name == "bt":
        return _pxas.bt
    if name == "server":
        return server
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# ---------------------------------------------------------------------------
# 14. CLI entry point
# ---------------------------------------------------------------------------


def main():
    import argparse

    parser = argparse.ArgumentParser(description="pxas — Proxmox scripting helper")
    parser.add_argument("-c", "--command", help="Python one-liner to execute")
    parser.add_argument("script", nargs="?", help="Python script file to run")
    args = parser.parse_args()

    _registry = _pxas
    _ns = {
        "px": _registry.px,
        "ct": _registry.ct,
        "nt": _registry.nt,
        "vt": _registry.vt,
        "st": _registry.st,
        "bt": _registry.bt,
        "cfg": cfg,
        "server": _registry.server,
    }

    if args.command or args.script:
        _cfg = cfg
        _registry = _pxas
        _px, _ct, _nt, _vt, _st, _bt = (
            _registry.px,
            _registry.ct,
            _registry.nt,
            _registry.vt,
            _registry.st,
            _registry.bt,
        )
        if args.script:
            script_dir = Path(args.script).resolve().parent
            _cfg = _load_config(extra_dirs=[script_dir])
            if _cfg.loaded_from != cfg.loaded_from or _cfg.default_server != cfg.default_server:
                _registry = _ServerRegistry(_cfg)
                default_proxy = _registry.server()
                if default_proxy._server_config().get("proxmox", {}).get("host"):
                    _px = default_proxy.px
                    _ct = default_proxy.ct
                    _nt = default_proxy.nt
                    _vt = default_proxy.vt
                    _st = default_proxy.st
                    _bt = default_proxy.bt
        if _px is None:
            _ns = {
                "px": None,
                "ct": None,
                "nt": None,
                "vt": None,
                "st": None,
                "bt": None,
                "cfg": _cfg,
                "server": _registry.server,
            }
        else:
            _ns = {
                "px": _px,
                "ct": _ct,
                "nt": _nt,
                "vt": _vt,
                "st": _st,
                "bt": _bt,
                "cfg": _cfg,
                "server": _registry.server,
            }
        if args.command:
            exec(args.command, _ns)
        else:
            with open(args.script) as f:
                exec(compile(f.read(), args.script, "exec"), _ns)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
