import 'dart:io';

/// Reports disk usage for a user-selected directory.
Future<String> diskUsage(String userDir) async {
  // Shell string is built from user input and handed to sh -c.
  final result = await Process.run('sh', ['-c', 'du -sh $userDir']);
  if (result.exitCode != 0) {
    throw ProcessException('sh', ['-c'], result.stderr as String);
  }
  return result.stdout as String;
}

/// Converts an uploaded image to a thumbnail.
Future<void> convertUpload(String inputPath) async {
  // runInShell interprets metacharacters in inputPath.
  await Process.start(
    'convert $inputPath /tmp/thumb.png',
    [],
    runInShell: true,
  );
}
