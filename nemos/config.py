from __future__ import annotations
import os
from dataclasses import dataclass
from math import isfinite
from pathlib import Path

from .ownership import give_back

def _int(name: str, default: int, lo: int, hi: int) -> int:
    try: value = int(os.getenv(name, default))
    except (TypeError, ValueError): value = default
    return max(lo, min(hi, value))

def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    return default if v is None else v.lower() in {"1", "true", "yes", "on"}

def _float(name: str, default: float, lo: float, hi: float) -> float:
    try:
        value = float(os.getenv(name, default))
    except (TypeError, ValueError):
        value = default
    return max(lo, min(hi, value)) if isfinite(value) else default

@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    interface: str | None
    db_path: Path
    api_token: str | None
    capture_enabled: bool
    max_traffic: int
    max_alerts: int
    batch_size: int
    flush_seconds: float
    dashboard_limit: int
    log_level: str
    trusted_hosts: tuple[str, ...] = ()
    api_rate_limit: int = 240
    api_auth_rate_limit: int = 10
    # Windowed flow analysis and ML anomaly detection.
    analysis_enabled: bool = True
    analysis_window: float = 10.0
    max_flows: int = 20_000
    persist_flows: bool = True
    model_dir: Path | None = None
    @property
    def remote(self): return self.host not in {"127.0.0.1","localhost","::1"}

def load_settings(base: Path | None = None) -> Settings:
    base = (base or Path.cwd()).resolve()
    data = base / "data"
    data.mkdir(parents=True, exist_ok=True)
    give_back(data)
    try:
        data.chmod(0o700)
    except OSError:
        # Some filesystems/platforms do not support POSIX mode changes.
        pass
    host = os.getenv("NEMOS_HOST","127.0.0.1").strip()
    token = os.getenv("NEMOS_API_TOKEN") or None
    trusted_raw = os.getenv("NEMOS_TRUSTED_HOSTS", "")
    trusted_hosts = tuple(sorted({h.strip() for h in trusted_raw.split(",") if h.strip()}))
    s = Settings(
        host, _int("NEMOS_PORT",5000,1,65535),
        os.getenv("NEMOS_INTERFACE") or None,
        Path(os.getenv("NEMOS_DB",str(data/"nemos.db"))).expanduser(),
        token, _bool("NEMOS_CAPTURE",True),
        _int("NEMOS_MAX_TRAFFIC",100_000,1000,2_000_000),
        _int("NEMOS_MAX_ALERTS",10_000,100,500_000),
        _int("NEMOS_DB_BATCH",250,1,5000),
        _float("NEMOS_DB_FLUSH_SECONDS", 0.5, 0.01, 60.0),
        _int("NEMOS_DASHBOARD_LIMIT",100,10,500),
        os.getenv("NEMOS_LOG_LEVEL","INFO").upper(),
        trusted_hosts,
        # Generous by default: the dashboard polls four endpoints every five
        # seconds, roughly 48 requests a minute, so the limit must not fight
        # normal use. The auth limit is the security-relevant one and is far
        # tighter, because nothing legitimate retries a rejected token.
        _int("NEMOS_API_RATE", 240, 10, 100_000),
        _int("NEMOS_API_AUTH_RATE", 10, 1, 10_000),
        _bool("NEMOS_ANALYSIS", True),
        _float("NEMOS_ANALYSIS_WINDOW", 10.0, 1.0, 300.0),
        _int("NEMOS_MAX_FLOWS", 20_000, 100, 1_000_000),
        _bool("NEMOS_PERSIST_FLOWS", True),
        Path(os.getenv("NEMOS_MODEL_DIR", str(data/"model"))).expanduser(),
    )
    if s.remote and not s.api_token:
        raise ValueError("Remote bind requires NEMOS_API_TOKEN; keep host=127.0.0.1 for local use.")
    if s.remote and s.host in {"0.0.0.0", "::", "*"} and not s.trusted_hosts:
        raise ValueError("Wildcard remote bind requires NEMOS_TRUSTED_HOSTS")
    if s.flush_seconds <= 0: raise ValueError("NEMOS_DB_FLUSH_SECONDS must be > 0")
    return s
