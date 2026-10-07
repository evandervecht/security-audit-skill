# SA-PY-02: Code injection via eval() (VULNERABLE)

def calculate(expression: str) -> float:
    return eval(expression)
