# SA-PY-05: Safe YAML loading with safe_load (SAFE)
import yaml

def parse_config(config_str: str) -> dict:
    return yaml.safe_load(config_str)
