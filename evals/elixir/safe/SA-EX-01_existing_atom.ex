defmodule MyApp.RoleController do
  use MyAppWeb, :controller

  @allowed ~w(admin editor viewer)

  # SAFE: validate against an allowlist and convert with
  # String.to_existing_atom, which only succeeds for atoms that already
  # exist — the atom table cannot grow from user input.
  def assign(conn, %{"role" => role}) when role in @allowed do
    role_atom = String.to_existing_atom(role)
    do_assign(conn, role_atom)
  end

  defp do_assign(conn, role_atom), do: assign(conn, :role, role_atom)
end
