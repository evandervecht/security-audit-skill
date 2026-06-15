defmodule MyApp.RoleController do
  use MyAppWeb, :controller

  # VULNERABLE: String.to_atom on user input creates a new atom for every
  # distinct value. Atoms are never garbage collected, so an attacker can
  # exhaust the BEAM atom table (default limit ~1M) and crash the VM (DoS).
  def assign(conn, %{"role" => role}) do
    role_atom = String.to_atom(role)
    do_assign(conn, role_atom)
  end

  defp do_assign(conn, role_atom), do: assign(conn, :role, role_atom)
end
