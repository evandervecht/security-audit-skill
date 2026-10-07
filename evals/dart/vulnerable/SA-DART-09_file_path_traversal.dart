import 'dart:io';

const uploadRoot = '/srv/uploads';

/// Serves a previously uploaded file back to the client.
Future<void> handleDownload(HttpRequest request) async {
  // ?file=../../etc/passwd walks out of the upload directory.
  final file = File('$uploadRoot/${request.uri.queryParameters['file']}');
  if (!await file.exists()) {
    request.response.statusCode = HttpStatus.notFound;
    await request.response.close();
    return;
  }
  await file.openRead().pipe(request.response);
}

/// Deletes an attachment named by the client.
Future<void> handleDelete(HttpRequest request) async {
  final name = request.uri.queryParameters['name'] ?? '';
  final target = File(uploadRoot + '/' + request.uri.queryParameters['name']!);
  if (name.isNotEmpty && await target.exists()) {
    await target.delete();
  }
  await request.response.close();
}
