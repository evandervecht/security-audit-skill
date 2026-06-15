defmodule MyApp.Calculator do
  use MyAppWeb, :controller

  # SAFE: never use Code.eval_string on user input. Delegate to a
  # purpose-built parser/evaluator that only understands arithmetic.
  def run(conn, %{"expr" => expr}) do
    result = MyApp.SafeMath.evaluate(expr)
    json(conn, %{result: result})
  end
end
