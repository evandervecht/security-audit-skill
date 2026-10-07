import 'dart:async';

import 'package:flutter/material.dart';
import 'package:uni_links/uni_links.dart';

const _linkHost = 'links.example.com';
const _allowedPaths = {'/orders', '/profile', '/promo'};

class DeepLinkHandler {
  StreamSubscription<Uri?>? _sub;

  /// Every incoming link is validated before it can steer navigation.
  void init(BuildContext context) {
    _sub = uriLinkStream.listen((Uri? uri) {
      if (uri == null ||
          uri.scheme != 'https' ||
          uri.host != _linkHost ||
          !_allowedPaths.contains(uri.path)) {
        return;
      }
      Navigator.pushNamed(context, uri.path);
    });
  }

  void dispose() {
    _sub?.cancel();
  }
}
