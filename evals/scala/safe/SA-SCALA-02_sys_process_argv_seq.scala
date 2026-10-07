package com.example.ops

import scala.sys.process._

object HostChecker {
  private val HostPattern = "[A-Za-z0-9.-]{1,253}"

  // Fixed argv vector: each element is passed to exec directly, no shell.
  def ping(host: String): String = {
    require(host.matches(HostPattern), "invalid hostname")
    Seq("ping", "-c", "1", host).!!
  }

  def diskUsage(dir: String): Int =
    Seq("du", "-sh", dir).!

  // Fully literal maintenance script: nothing dynamic ever reaches the
  // shell, so there is no injection surface despite the sh -c form.
  def compactLogs(): Int =
    Seq("sh", "-c", "find /var/log/app -name '*.gz' -mtime +30 -delete").!
}
