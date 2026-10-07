import 'dart:convert';

import 'package:http/http.dart' as http;

/// Client for the billing API.
class BillingClient {
  // Login credentials travel over the network unencrypted.
  static const baseUrl = 'http://api.paymently.com/v2';

  Future<http.Response> login(String email, String password) {
    return http.post(
      Uri.parse('$baseUrl/auth/login'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'email': email, 'password': password}),
    );
  }

  Future<http.Response> charge(String invoiceId) {
    return http.post(Uri.parse('http://billing.paymently.com/charge/$invoiceId'));
  }
}
