import 'dart:async';

import 'package:flutter/material.dart';
import 'package:uni_links/uni_links.dart';

const _allowedRoutes = {'/orders', '/profile'};

/// Compact guard style: single-line returns reject invalid links before
/// any navigation, and only the validated path reaches the route table.
class GuardedDeepLinkHandler {
  StreamSubscription<Uri?>? _sub;

  void init(BuildContext context) {
    _sub = uriLinkStream.listen((Uri? uri) {
      if (uri == null || uri.scheme != 'https') return;
      if (uri.host != 'links.example.com') return;
      if (!_allowedRoutes.contains(uri.path)) return;
      Navigator.pushNamed(context, uri.path);
    });
  }

  void dispose() {
    _sub?.cancel();
  }
}
