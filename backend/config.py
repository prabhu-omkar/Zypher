import os
import sys
from typing import Optional
from pydantic import BaseModel


def _get_storage_dir():
    """Get storage directory — uses exe directory in frozen mode, project root in dev."""
    if getattr(sys, 'frozen', False):
        # Packaged exe: store data next to the executable
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    return os.path.join(base, "data_store")


class AppConfig(BaseModel):
    app_name: str = "Zypher — Cryptographic Discovery & Quantum Risk Analysis"
    problem_statement_id: str = "26164"
    organization: str = "National Technical Research Organisation (NTRO)"
    default_mosca_z: float = 8.0 # Default CRQC arrival timeline in years
    default_shelf_life_x: float = 7.0
    default_migration_time_y: float = 2.0
    mongo_uri: Optional[str] = os.getenv("ECDAT_MONGO_URI", None)
    db_name: str = os.getenv("ECDAT_DB_NAME", "ecdat_enterprise_inventory")
    is_standalone_fallback: bool = True
    storage_dir: str = _get_storage_dir()

    # Known-vulnerability lookup is the one feature that reaches the network, so
    # it is off unless explicitly enabled. Everything else works fully offline
    # and must keep doing so.
    vulnerability_lookup_enabled: bool = (
        os.getenv("ECDAT_VULN_LOOKUP", "").lower() in ("1", "true", "yes")
    )

    # Tier 4 dataflow analysis. On by default — it is fully offline and it is what
    # makes key sizes trustworthy rather than assumed. It is switchable because it
    # spawns a subprocess with a fixed start-up cost of roughly two seconds, which
    # is worth avoiding when scanning a very large tree repeatedly.
    dataflow_analysis_enabled: bool = (
        os.getenv("ECDAT_DATAFLOW", "1").lower() not in ("0", "false", "no")
    )


config = AppConfig()
os.makedirs(config.storage_dir, exist_ok=True)
