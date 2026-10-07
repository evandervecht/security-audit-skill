import 'dart:isolate';

/// Entry point compiled into the app binary; nothing is fetched remotely.
void pluginWorker(SendPort send) {
  send.send('plugin-ready');
}

class PluginRunner {
  final ReceivePort _port = ReceivePort();

  /// Runs the bundled worker in a background isolate.
  Future<Isolate> startWorker() {
    return Isolate.spawn(pluginWorker, _port.sendPort);
  }

  void dispose() {
    _port.close();
  }
}
