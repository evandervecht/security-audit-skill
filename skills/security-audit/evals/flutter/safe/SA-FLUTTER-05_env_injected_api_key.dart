/// Map configuration for the store-locator screen.
class MapsConfig {
  // Injected at build time: flutter build apk --dart-define=MAPS_API_KEY=...
  // CI holds the real value; the repo and binary diff per environment.
  static const String mapsApiKey = String.fromEnvironment('MAPS_API_KEY');
  static const stripePublishable = String.fromEnvironment('STRIPE_PUBLISHABLE');

  // Documentation placeholder, not a real credential.
  static const String demoApiKey = 'REPLACE_WITH_YOUR_API_KEY';

  // Remote-config parameter name that selects which key to fetch; the
  // value is a lookup identifier, not a credential.
  static const String remoteConfigApiKey = 'maps_api_key_android';

  // Versioned lookup name, still an identifier rather than key material.
  static const String googleMapsApiKey = 'google_maps_api_key_v2';
}

class StoreLocator {
  Uri tileUrl(double lat, double lng) {
    return Uri.https('maps.googleapis.com', '/maps/api/staticmap', {
      'center': '$lat,$lng',
      'zoom': '14',
      'key': MapsConfig.mapsApiKey,
    });
  }
}
