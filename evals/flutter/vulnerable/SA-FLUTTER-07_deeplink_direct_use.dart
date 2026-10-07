import 'dart:async';

import 'package:uni_links/uni_links.dart';
import 'package:webview_flutter/webview_flutter.dart';

class DeepLinkHandler {
  StreamSubscription<Uri?>? _sub;

  /// Any app on the device can craft a link that lands here.
  void init(WebViewController controller) {
    _sub = uriLinkStream.listen((Uri? uri) {
      if (uri != null) controller.loadRequest(uri);
    });
  }

  void dispose() {
    _sub?.cancel();
  }
}
