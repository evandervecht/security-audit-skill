# SA-PY-06: Safe YAML loading with an explicit SafeLoader (SAFE)
import yaml


def parse_config(config_str: str) -> dict:
    return yaml.load(config_str, Loader=yaml.SafeLoader)
