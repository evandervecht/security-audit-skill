defmodule MyApp.Calculator do
  use MyAppWeb, :controller

  # VULNERABLE: Code.eval_string compiles and runs arbitrary Elixir.
  # An attacker sending expr="System.cmd(\"sh\", [\"-c\", \"id\"])" gets RCE.
  def run(conn, %{"expr" => expr}) do
    {result, _binding} = Code.eval_string(expr)
    json(conn, %{result: result})
  end
end
