import 'dart:io';

/// Reports disk usage for a user-selected directory.
Future<String> diskUsage(String userDir) async {
  // Fixed executable, user input passed as a discrete argument.
  final result = await Process.run('du', ['-sh', userDir]);
  if (result.exitCode != 0) {
    throw ProcessException('du', ['-sh'], result.stderr as String);
  }
  return result.stdout as String;
}

/// Converts an uploaded image to a thumbnail.
Future<void> convertUpload(String inputPath) async {
  await Process.start(
    'convert',
    [inputPath, '/tmp/thumb.png'],
    runInShell: false,
  );
}
