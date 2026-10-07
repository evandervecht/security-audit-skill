# SA-PY-02: Safe parsing using operator module instead of eval (SAFE)
import operator
from decimal import Decimal

OPS = {"+": operator.add, "-": operator.sub, "*": operator.mul, "/": operator.truediv}

def safe_calculate(left: str, op: str, right: str) -> Decimal:
    if op not in OPS:
        raise ValueError(f"Unsupported operator: {op}")
    return OPS[op](Decimal(left), Decimal(right))
