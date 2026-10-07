import 'package:flutter_inappwebview/flutter_inappwebview.dart';

/// Embeds the fixed first-party checkout page via the inappwebview API.
class CheckoutView {
  Future<void> openCheckout(InAppWebViewController controller) {
    // The URL is a fixed literal passed through the urlRequest named
    // parameter; no user-controlled value reaches the WebView.
    return controller.loadUrl(
      urlRequest: URLRequest(
        url: WebUri('https://checkout.example.com/embedded'),
      ),
    );
  }
}
