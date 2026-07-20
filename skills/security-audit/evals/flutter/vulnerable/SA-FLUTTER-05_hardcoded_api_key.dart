/// Map configuration for the store-locator screen.
class MapsConfig {
  // Extractable with `strings app.apk`; billed to our account when abused.
  static const String mapsApiKey = 'AIzaSyB8mXk29qLmNoPqRsTuVwXyZ0123456789ab';
  static const stripeKey = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc8FhYq2';
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
