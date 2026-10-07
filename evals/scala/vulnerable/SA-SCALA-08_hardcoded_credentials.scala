package com.example.config

object DbConfig {
  val dbHost = "db.internal.example.com"
  val dbUser = "app_rw"
  // Checked into git; rotating it now means redeploying every service.
  val dbPassword = "Sup3rS3cretPass!2024"
  val stripeApiKey = "sk_live_51HxTESTfake1234567890"
  val jwtSigningSecret = "change-me-in-prod-never-changed"
  val backupSftpCredentials = "backup:Tr4nsf3r!Passphrase"
  val LEGACY_FTP_PASSWORD = "Xfer!2019-LegacyHost"

  def jdbcUrl: String =
    "jdbc:postgresql://" + dbHost + ":5432/app"
}
