# SA-RB-03: system() with string interpolation — command injection
def ping_host(hostname)
  system("ping -c 1 #{hostname}")
end

# Attacker sends: "example.com; cat /etc/passwd"
ping_host(ARGV[0])
