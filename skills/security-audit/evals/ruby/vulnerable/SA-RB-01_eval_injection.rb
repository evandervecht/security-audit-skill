# SA-RB-01: eval() with user-controlled input — code injection
def calculate(user_expression)
  result = eval(user_expression)
  puts "Result: #{result}"
  result
end

# Attacker sends: "system('cat /etc/passwd')"
calculate(gets.chomp)
