import os
import json
import sys

def get_app_data_dir():
    """Get persistent directory for ECDAT installation and configuration."""
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        app_dir = os.path.join(local_app_data, "Programs", "ECDAT")
    else:
        app_dir = os.path.abspath(os.path.dirname(__file__))
    os.makedirs(app_dir, exist_ok=True)
    return app_dir

def get_config_file_path():
    # Check if config exists in same directory as executable
    exe_dir = os.path.abspath(os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else __file__))
    local_config = os.path.join(exe_dir, "ecdat_config.json")
    if os.path.exists(local_config):
        return local_config

    # Check %LOCALAPPDATA%
    return os.path.join(get_app_data_dir(), "ecdat_config.json")

def load_saved_config():
    config_path = get_config_file_path()
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return None

def save_config(mongo_uri: str, database_name: str = "ecdat_enterprise_inventory", is_installed: bool = True):
    config_path = get_config_file_path()
    data = {
        "mongo_uri": mongo_uri,
        "database_name": database_name or "ecdat_enterprise_inventory",
        "is_installed": is_installed
    }
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"Failed to save config: {e}")
        return False
