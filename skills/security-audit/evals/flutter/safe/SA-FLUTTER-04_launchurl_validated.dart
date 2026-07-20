import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

const _allowedHosts = {'example.com', 'www.example.com', 'blog.example.com'};

/// Button on a user profile that opens their "website" field.
class ProfileLinkButton extends StatelessWidget {
  /// Free-text value another user typed into their profile.
  final String websiteUrl;

  const ProfileLinkButton({super.key, required this.websiteUrl});

  Future<void> _open() async {
    final uri = Uri.tryParse(websiteUrl);
    if (uri == null) return;
    // Scheme and host are checked before anything is launched.
    if (uri.scheme != 'https' || !_allowedHosts.contains(uri.host)) {
      return;
    }
    await launchUrl(uri, mode: LaunchMode.externalApplication);
  }

  @override
  Widget build(BuildContext context) {
    return TextButton(onPressed: _open, child: const Text('Website'));
  }
}

/// A fixed literal URL needs no runtime validation.
Future<void> openTerms() {
  return launchUrl(Uri.parse('https://example.com/terms'));
}
