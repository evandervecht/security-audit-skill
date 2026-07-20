package com.example.tools

object NetworkDiag {
  // "host" is read from a form field on the diagnostics page.
  def ping(host: String): Process =
    Runtime.getRuntime.exec("ping -c 1 " + host)

  // Interpolation has the same effect as concatenation here.
  def trace(host: String): Process =
    Runtime.getRuntime().exec(s"traceroute -m 10 $host")

  def readOutput(p: Process): String =
    scala.io.Source.fromInputStream(p.getInputStream).mkString
}
