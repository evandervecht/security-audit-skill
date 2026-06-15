# SA-PY-02: Code injection via eval() on user input (VULNERABLE)


def calculate(expression: str) -> float:
    return eval(expression)
