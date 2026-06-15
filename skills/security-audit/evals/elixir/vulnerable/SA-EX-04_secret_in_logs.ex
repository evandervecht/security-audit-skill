defmodule MyApp.Auth do
  require Logger

  # VULNERABLE: secrets end up in plaintext log files / aggregators.
  def login(user, password, token) do
    Logger.info("Login attempt: #{inspect(password)}")
    Logger.debug("API token=#{inspect(token)} secret=#{inspect(user.secret_key)}")
    do_login(user)
  end

  defp do_login(user), do: {:ok, user}
end
