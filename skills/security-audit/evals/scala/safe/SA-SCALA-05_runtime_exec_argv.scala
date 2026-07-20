package com.example.tools

object NetworkDiag {
  private val HostPattern = "[A-Za-z0-9.-]{1,253}"

  // Array overload: arguments are passed to execve directly, never a shell.
  def ping(host: String): Process = {
    require(host.matches(HostPattern), "invalid hostname")
    Runtime.getRuntime.exec(Array("ping", "-c", "1", host))
  }

  def trace(host: String): Process = {
    require(host.matches(HostPattern), "invalid hostname")
    Runtime.getRuntime.exec(Array("traceroute", "-m", "10", host))
  }

  def readOutput(p: Process): String =
    scala.io.Source.fromInputStream(p.getInputStream).mkString

  // Static command, no interpolation and no concatenation: nothing an
  // attacker controls ever reaches the command line.
  def uptime(): Process =
    Runtime.getRuntime.exec(s"uptime")
}
