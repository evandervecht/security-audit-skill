import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

/// Opens a help-center article by its numeric identifier.
class HelpArticleWebView extends StatelessWidget {
  /// Only the article id travels through navigation, never a URL.
  final int articleId;

  const HelpArticleWebView({super.key, required this.articleId});

  @override
  Widget build(BuildContext context) {
    // Scheme and host are fixed; the id is path-encoded by Uri.https.
    final controller = WebViewController()
      ..loadRequest(Uri.https('help.example.com', '/articles/$articleId'));
    return Scaffold(
      appBar: AppBar(title: const Text('Help')),
      body: WebViewWidget(controller: controller),
    );
  }
}
