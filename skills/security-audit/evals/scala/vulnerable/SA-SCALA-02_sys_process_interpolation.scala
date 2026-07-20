package com.example.ops

import scala.sys.process._

object HostChecker {
  // "host" comes straight from an HTTP query parameter.
  def ping(host: String): String =
    s"ping -c 1 $host".!!

  // Same bug through an explicit shell: the payload is one shell word.
  def diskUsage(dir: String): Int =
    Seq("sh", "-c", "du -sh " + dir).!
}
