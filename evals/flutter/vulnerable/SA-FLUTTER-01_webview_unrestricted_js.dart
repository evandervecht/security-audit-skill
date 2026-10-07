import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

/// Renders third-party ad content inside the app.
class AdWebView extends StatelessWidget {
  final String adHtml;

  const AdWebView({super.key, required this.adHtml});

  @override
  Widget build(BuildContext context) {
    // Untrusted ad markup runs with full JavaScript enabled.
    final controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..loadHtmlString(adHtml);
    return WebViewWidget(controller: controller);
  }
}
