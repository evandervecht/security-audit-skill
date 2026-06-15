defmodule MyApp.Ping do
  # SAFE: System.cmd with the executable and an explicit argument list.
  # No shell is spawned and arguments are passed directly to execve,
  # so metacharacters in `host` / `file` are treated as literal data.
  def ping(host) do
    System.cmd("ping", ["-c", "1", host])
  end

  def convert(file) do
    System.cmd("convert", [file, "out.png"])
  end
end
