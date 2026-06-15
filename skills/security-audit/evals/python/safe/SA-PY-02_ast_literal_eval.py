# SA-PY-02: Safe parsing via ast.literal_eval (SAFE)
import ast


def calculate(expression: str):
    # literal_eval only evaluates Python literals, never arbitrary code
    return ast.literal_eval(expression)
