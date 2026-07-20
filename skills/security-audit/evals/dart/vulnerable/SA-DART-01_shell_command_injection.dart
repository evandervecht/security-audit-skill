import 'dart:io';

class ArchiveService {
  Future<String> compressLogs(String userDir) async {
    // Request parameter is spliced into a shell command line.
    final result =
        await Process.run('sh', ['-c', 'tar czf /tmp/logs.tgz $userDir']);
    if (result.exitCode != 0) {
      throw Exception('compress failed: ${result.stderr}');
    }
    return '/tmp/logs.tgz';
  }

  Future<void> ping(String host) async {
    // runInShell hands the whole line to the platform shell.
    await Process.start('ping', ['-c', '4', host], runInShell: true);
  }
}
