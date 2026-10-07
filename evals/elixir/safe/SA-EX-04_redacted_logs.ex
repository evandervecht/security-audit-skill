defmodule MyApp.Auth do
  require Logger

  # SAFE: log only non-sensitive identifiers. Secrets are redacted and
  # struct fields holding them should also use the @derive Inspect
  # except: filter so accidental inspect/1 calls never expose them.
  def login(user, _password, _token) do
    Logger.info("Login attempt for user=#{inspect(user.id)}")
    Logger.debug("Auth ok for #{inspect(user.email)}")
    do_login(user)
  end

  defp do_login(user), do: {:ok, user}
end
