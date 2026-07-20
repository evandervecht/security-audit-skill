import 'package:postgres/postgres.dart';

/// Connection settings for the reporting database.
class ReportingConfig {
  static const String dbHost = 'reports.internal.example.com';
  static const int dbPort = 5432;

  // Credentials committed straight into source control.
  static const String dbPassword = 'Sup3rS3cretDbPass_2026';
  static const String serviceToken = 'svc_9f8e7d6c5b4a3210fedcba98';
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
