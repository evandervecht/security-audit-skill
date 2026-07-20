package com.example.config

import com.typesafe.config.ConfigFactory

object DbConfig {
  private val config = ConfigFactory.load()

  val dbHost = "db.internal.example.com"
  val dbUser = sys.env.getOrElse("DB_USER", "app_rw")
  // Identifiers that merely contain a secret-ish word are not secrets.
  val tokenizer = "whitespace-and-punctuation"
  val tokenEndpoint = "https://auth.example.com/oauth2/token"
  val tokenHeaderName = "X-Auth-Token"
  val passwordFieldName = "current_password"
  val secretsMountPath = "/var/run/secrets/app"
  val TOKEN_HEADER = "X-Custom-Auth-Token"
  val SECRETS_FILE_PATH = "/etc/app/secrets.yml"
  // Secrets are injected at runtime and never committed.
  val dbPassword = sys.env("DB_PASSWORD")
  val stripeApiKey = config.getString("stripe.api-key")
  val jwtSigningSecret = sys.env("JWT_SIGNING_SECRET")

  def jdbcUrl: String =
    "jdbc:postgresql://" + dbHost + ":5432/app"
}
