import 'dart:convert';

import 'package:http/http.dart' as http;

/// Client for the billing API.
class BillingClient {
  // All production traffic is TLS; plain http is confined to localhost dev.
  static const baseUrl = 'https://api.paymently.com/v2';
  static const localDevUrl = 'http://localhost:8080/v2';

  // XML namespace identifier used when building invoices, not an endpoint.
  static const svgNamespace = 'http://www.w3.org/2000/svg';

  Future<http.Response> login(String email, String password) {
    return http.post(
      Uri.parse('$baseUrl/auth/login'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'email': email, 'password': password}),
    );
  }

  Future<http.Response> charge(String invoiceId) {
    return http.post(Uri.parse('https://billing.paymently.com/charge/$invoiceId'));
  }
}
