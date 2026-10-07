import 'dart:isolate';

/// Loads a "plugin" from a URL stored in the remote app config.
class PluginLoader {
  final ReceivePort _port = ReceivePort();

  /// The plugin URL comes from a server-controlled JSON document.
  Future<Isolate> loadPlugin(String pluginUrl) {
    // Downloads and executes arbitrary Dart code from the network.
    return Isolate.spawnUri(
      Uri.parse(pluginUrl),
      <String>['start'],
      _port.sendPort,
    );
  }

  void dispose() {
    _port.close();
  }
}
