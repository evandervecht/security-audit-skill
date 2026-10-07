import 'dart:io';

import 'package:cross_file/cross_file.dart';
import 'package:path/path.dart' as p;

const uploadRoot = '/srv/uploads';

/// XFile is the picker-result wrapper from cross_file, not a dart:io File;
/// constructing one performs no filesystem access.
XFile stagedAvatar(String cacheDir, String userAvatarName) {
  return XFile('$cacheDir/$userAvatarName');
}

/// The invoking user's home directory comes from the process environment,
/// not from a request: a benign path prefix, not attacker input.
Future<String> readOwnConfig() {
  final userHome = Platform.environment['HOME'] ?? '/root';
  return File('$userHome/.config/uploader.conf').readAsString();
}

/// Serves a previously uploaded file back to the client.
Future<void> handleDownload(HttpRequest request) async {
  final requested = request.uri.queryParameters['file'] ?? '';
  // basename strips any directory components the client sent.
  final safeName = p.basename(requested);
  final file = File('$uploadRoot/$safeName');
  final resolved = p.normalize(file.path);
  if (safeName.isEmpty || !p.isWithin(uploadRoot, resolved)) {
    request.response.statusCode = HttpStatus.badRequest;
    await request.response.close();
    return;
  }
  if (!await file.exists()) {
    request.response.statusCode = HttpStatus.notFound;
    await request.response.close();
    return;
  }
  await file.openRead().pipe(request.response);
}
