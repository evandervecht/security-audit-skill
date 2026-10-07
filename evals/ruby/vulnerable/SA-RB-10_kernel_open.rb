# SA-RB-10: Kernel.open with user input — pipe injection and SSRF
def fetch_content(url)
  content = Kernel.open(url).read
  content
end

# Attacker sends url="|cat /etc/passwd"
puts fetch_content(ARGV[0])
