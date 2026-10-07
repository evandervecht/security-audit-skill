# SA-RB-01: safe expression parsing without eval
# Uses an allowlist approach instead of dynamic code execution
ALLOWED_OPS = {
  'add' => ->(a, b) { a + b },
  'sub' => ->(a, b) { a - b },
  'mul' => ->(a, b) { a * b }
}.freeze

def calculate(operation, operand_a, operand_b)
  handler = ALLOWED_OPS[operation]
  raise ArgumentError, "Unknown operation: #{operation}" unless handler
  handler.call(operand_a.to_f, operand_b.to_f)
end

puts calculate('add', 2, 3)
