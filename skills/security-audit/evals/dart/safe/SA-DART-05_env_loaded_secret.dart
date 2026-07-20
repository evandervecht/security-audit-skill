import 'dart:io';

import 'package:postgres/postgres.dart';

/// Connection settings for the reporting database.
class ReportingConfig {
  static const String dbHost = 'reports.internal.example.com';
  static const int dbPort = 5432;

  // Secrets come from the deployment environment, never from source.
  static String get dbPassword => Platform.environment['DB_PASSWORD'] ?? '';
  static const String serviceToken =
      String.fromEnvironment('SERVICE_TOKEN', defaultValue: '');

  // A storage key that merely names a credential is not itself a secret.
  static const String tokenPrefsKey = 'auth_token';

  // Key names and form-field identifiers are not credentials, even when a
  // version suffix adds a digit: no 8+ character digit-bearing run exists.
  static const String legacyTokenPrefsKey = 'reporting_service_token';
  static const String tokenStorageKey = 'auth_token_v2';
  static const String sessionTokenKey = 'session_token_2024';
  static const String passwordField = 'password';
}

Future<Connection> openReportingDb() {
  return Connection.open(
    Endpoint(
      host: ReportingConfig.dbHost,
      port: ReportingConfig.dbPort,
      database: 'reports',
      username: 'reporting',
      password: ReportingConfig.dbPassword,
    ),
  );
}
