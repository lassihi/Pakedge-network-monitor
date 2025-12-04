import os
from pathlib import Path


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def config_path() -> Path:
    return project_root() / "src" / "pakedge-monitor" / "config.yaml"


def database_path() -> Path:
    db_override = os.environ.get("PAKEDGE_DB")
    local_data_path = project_root() / "data" / "network.db"
    container_data_path = Path("/data/network.db")

    if db_override:
        db_path = Path(db_override)
    elif container_data_path.parent.exists():
        db_path = container_data_path
    else:
        db_path = local_data_path

    db_path.parent.mkdir(parents=True, exist_ok=True)
    return db_path
