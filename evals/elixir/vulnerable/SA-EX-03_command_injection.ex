defmodule MyApp.Ping do
  # VULNERABLE: :os.cmd runs a shell string. Interpolating host allows
  # injection: host="127.0.0.1; rm -rf /".
  def ping(host) do
    :os.cmd(~c"ping -c 1 #{host}")
  end

  # VULNERABLE: invoking sh -c with an interpolated string is shell
  # injection even via System.cmd.
  def convert(file) do
    System.cmd("sh", ["-c", "convert #{file} out.png"])
  end
end
