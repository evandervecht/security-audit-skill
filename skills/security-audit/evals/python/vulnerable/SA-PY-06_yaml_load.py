# SA-PY-05: Unsafe YAML loading (VULNERABLE)
import yaml

def parse_config(config_str: str) -> dict:
    return yaml.load(config_str)
