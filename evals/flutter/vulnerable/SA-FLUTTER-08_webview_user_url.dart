import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

/// Opens the article link found in a user-submitted feed item.
class ArticleWebView extends StatelessWidget {
  /// Value comes from a feed other users can post into.
  final String articleUrl;

  const ArticleWebView({super.key, required this.articleUrl});

  @override
  Widget build(BuildContext context) {
    // javascript:, file:// and attacker-hosted pages all load here.
    final controller = WebViewController()
      ..loadRequest(Uri.parse(articleUrl));
    return Scaffold(
      appBar: AppBar(title: const Text('Article')),
      body: WebViewWidget(controller: controller),
    );
  }
}
