# SA-PY-06: Unsafe YAML loading via full_load (VULNERABLE)
import yaml


def parse_config(config_str: str) -> dict:
    # full_load resolves full YAML tags -> object construction / code execution risk
    return yaml.full_load(config_str)
