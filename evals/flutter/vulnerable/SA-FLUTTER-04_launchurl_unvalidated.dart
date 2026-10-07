import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:url_launcher/url_launcher_string.dart';

/// Button on a user profile that opens their "website" field.
class ProfileLinkButton extends StatelessWidget {
  /// Free-text value another user typed into their profile.
  final String websiteUrl;

  const ProfileLinkButton({super.key, required this.websiteUrl});

  Future<void> _open() async {
    // tel:, sms:, file: and intent: URIs all launch unchecked.
    await launchUrlString(websiteUrl);
  }

  Future<void> _openBanner(String bannerTarget) async {
    await launchUrl(Uri.parse(bannerTarget));
  }

  @override
  Widget build(BuildContext context) {
    return TextButton(onPressed: _open, child: const Text('Website'));
  }
}
