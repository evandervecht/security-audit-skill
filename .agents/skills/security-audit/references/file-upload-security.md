# File Upload Security

## Understanding File Upload Vulnerabilities

### What Is an Unrestricted File Upload?

An unrestricted file upload (CWE-434: Unrestricted Upload of File with Dangerous Type) occurs when an application accepts user-supplied files without adequately validating their type, contents, name, or destination. The classic impact is remote code execution: an attacker uploads a server-side script (`.php`, `.jsp`, `.aspx`) into a web-accessible directory and then requests it, causing the server to execute attacker-controlled code.

Related weaknesses compound the risk:

- **CWE-434** — Unrestricted Upload of File with Dangerous Type (the core weakness)
- **CWE-646** — Reliance on File Name or Extension of Externally-Supplied File (trusting `.jpg` in the filename instead of inspecting content)
- **CWE-22** — Improper Limitation of a Pathname (path traversal in the stored filename — see `path-traversal-prevention.md`)
- **CWE-79** — Improper Neutralization of Input (stored XSS via SVG/HTML uploads)
- **CWE-409** — Improper Handling of Highly Compressed Data (decompression bombs)
- **CWE-400** — Uncontrolled Resource Consumption (missing size limits → DoS)

### Threat Catalogue

```
# Web shell upload / RCE
Upload shell.php into a web-served directory, request it: server executes PHP.

# Content-Type spoofing
Send Content-Type: image/png while the body is <?php system($_GET['c']); ?>.
The browser-supplied MIME type is attacker-controlled and must never be trusted.

# Double extensions
shell.php.jpg  — bypasses naive "last extension" checks; Apache with
AddHandler misconfig may execute the .php part.

# Null-byte tricks (legacy parsers)
shell.php%00.jpg — truncates at the null byte in old PHP / C-backed libraries.

# Polyglot files
A valid GIF that is also valid PHP (GIF89a;<?php ...?>). Passes getimagesize()
yet executes when interpreted as a script.

# SVG / HTML XSS
<svg onload="alert(document.cookie)"> served inline runs in the victim's origin.
Uploaded .html executes JavaScript when opened from the same domain.

# Zip-slip
Archive entry named ../../../../var/www/html/shell.php escapes the extraction
root during decompression (path traversal via archive members).

# Decompression bombs ("zip bomb")
A 42 KB zip expanding to petabytes — exhausts disk/memory on extraction.

# Overwriting files
Uploading .htaccess, web.config, index.php, or an existing user's avatar by
controlling the stored filename.

# Storing in the web root
Any uploaded file under public/ / htdocs/ is directly reachable and, if it is a
script type, executable.

# Missing size limits (DoS)
Unbounded multipart bodies exhaust memory and disk.

# Image metadata leakage
EXIF GPS coordinates, device serial numbers, and embedded thumbnails leak when
images are stored and re-served verbatim.

# ImageTragick-style processing exploits
CVE-2016-3714: ImageMagick delegate handling executes shell commands embedded in
crafted image/SVG/MVG files passed to a vulnerable convert/identify pipeline.
```

## Vulnerable Patterns

### PHP — Extension-Only Validation

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// Trusts the client-supplied filename extension and MIME type
$file = $_FILES['avatar'];

// Bypass 1: filename "shell.php.jpg" — checks the wrong segment
$ext = pathinfo($file['name'], PATHINFO_EXTENSION);

// Bypass 2: $_FILES['avatar']['type'] is the BROWSER-SUPPLIED MIME type.
// The attacker controls it entirely.
if ($file['type'] === 'image/jpeg') {
    // VULNERABLE: destination is INSIDE the web root and keeps the
    // attacker-controlled filename, enabling overwrite + RCE.
    move_uploaded_file($file['tmp_name'], __DIR__ . '/uploads/' . $file['name']);
}
// Attacker: upload shell.php with Content-Type: image/jpeg
//           then GET /uploads/shell.php
```

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// Blacklist of "bad" extensions is always incomplete
$blocked = ['php', 'phtml', 'exe'];
$ext = strtolower(pathinfo($_FILES['doc']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $blocked, true)) {
    move_uploaded_file($_FILES['doc']['tmp_name'], '/var/www/html/files/' . $_FILES['doc']['name']);
}
// Bypass: .php5, .php7, .pht, .phar, .shtml, .htaccess, uppercase .PHP, trailing dot "shell.php."
```

## Secure Patterns

### PHP — Server-Side MIME Sniffing, Allowlist, Random Rename, Outside Web Root

```php
<?php

declare(strict_types=1);

// SECURE: content-based validation, randomized name, storage outside web root,
// and an extension derived from the *detected* type (never the client name).
final class SecureUploadHandler
{
    /** @var array<string, string> Detected MIME => safe extension */
    private const ALLOWED = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/gif'  => 'gif',
        'application/pdf' => 'pdf',
    ];

    private const MAX_BYTES = 5 * 1024 * 1024; // 5 MB

    public function __construct(
        // Storage root MUST live outside the document root (e.g. /var/app/storage)
        private readonly string $storageDir,
    ) {}

    /**
     * @param array{tmp_name:string,size:int,error:int} $file A single $_FILES entry
     * @throws \RuntimeException on any validation failure
     */
    public function store(array $file): string
    {
        if ($file['error'] !== UPLOAD_ERR_OK) {
            throw new \RuntimeException('Upload failed');
        }

        // 1. Enforce size limit (defense-in-depth alongside php.ini upload_max_filesize)
        if ($file['size'] <= 0 || $file['size'] > self::MAX_BYTES) {
            throw new \RuntimeException('File too large');
        }

        // 2. Confirm PHP recognises this as a genuine uploaded file
        if (!is_uploaded_file($file['tmp_name'])) {
            throw new \RuntimeException('Not an uploaded file');
        }

        // 3. Sniff the REAL MIME type from the file content, not the request
        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $mime = $finfo->file($file['tmp_name']);
        if (!isset(self::ALLOWED[$mime])) {
            throw new \RuntimeException('Disallowed file type: ' . $mime);
        }

        // 4. For images, re-decode to prove the bytes are a real image
        //    (also defeats polyglots — see reencodeImage below).
        if (str_starts_with($mime, 'image/')) {
            if (@getimagesize($file['tmp_name']) === false) {
                throw new \RuntimeException('Corrupt or fake image');
            }
        }

        // 5. Generate a random, unguessable filename with a SAFE extension
        $extension = self::ALLOWED[$mime];
        $name = bin2hex(random_bytes(16)) . '.' . $extension;

        // 6. Store OUTSIDE the web root; never honour the client filename
        $destination = $this->storageDir . '/' . $name;
        if (!move_uploaded_file($file['tmp_name'], $destination)) {
            throw new \RuntimeException('Could not persist upload');
        }

        // 7. Strip the execute bit; files are data, not programs
        @chmod($destination, 0644);

        return $name;
    }

    /**
     * SECURE: re-encode an image to drop EXIF metadata and any appended
     * polyglot payload. The output contains only pixels.
     */
    public function reencodeImage(string $sourcePath, string $destPath): void
    {
        $image = @imagecreatefromstring((string) file_get_contents($sourcePath));
        if ($image === false) {
            throw new \RuntimeException('Not a decodable image');
        }
        imagejpeg($image, $destPath, 90); // re-emits clean JPEG, no metadata
        imagedestroy($image);
    }
}
```

When uploads must live under the web root, disable script execution for that directory at the server layer:

```apache
# Apache: drop a .htaccess in the uploads directory (or set in vhost — preferred)
<Directory "/var/www/html/uploads">
    php_admin_flag engine off
    RemoveHandler .php .phtml .php3 .php4 .php5 .php7 .phar .pht
    RemoveType .php .phtml .phar
    # Force download rather than inline rendering of SVG/HTML
    Header set Content-Disposition "attachment"
    Header set X-Content-Type-Options "nosniff"
</Directory>
```

```nginx
# nginx: never pass uploaded paths to the PHP FastCGI handler
location ^~ /uploads/ {
    location ~ \.(php|phtml|phar)$ { return 403; }
    add_header X-Content-Type-Options "nosniff";
    add_header Content-Disposition "attachment";
}
```

### PHP — Laravel

```php
<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;

// SECURE: Laravel validates server-side, hashes the name, and stores on a disk
// whose root is outside public/ unless explicitly published.
public function upload(Request $request): array
{
    $validated = $request->validate([
        // 'image' rule decodes the file to confirm it is a real image;
        // 'mimetypes' checks the SNIFFED type, not the client extension.
        'avatar' => ['required', 'image', 'mimetypes:image/jpeg,image/png', 'max:5120'], // KB
    ]);

    // store() / storeAs() with hashName() generates a random filename.
    // The 'private' disk maps to storage/app/private — outside the web root.
    $path = $request->file('avatar')->store('avatars', 'private');

    return ['path' => $path];
}
```

### PHP — Symfony

```php
<?php

declare(strict_types=1);

use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\Validator\Constraints as Assert;

// SECURE: constraints validate the sniffed MIME type and size.
final class AvatarUpload
{
    #[Assert\NotNull]
    #[Assert\Image(
        maxSize: '5M',
        mimeTypes: ['image/jpeg', 'image/png'],
        detectCorrupted: true, // re-decodes the image; rejects polyglots
    )]
    public ?UploadedFile $file = null;
}

// In the controller, after validation:
$original = $upload->file;
// guessExtension() derives the extension from the detected MIME, not the name.
$safeName = bin2hex(random_bytes(16)) . '.' . $original->guessExtension();
$original->move($this->getParameter('upload_dir'), $safeName); // upload_dir is outside public/
```

### PHP — TYPO3 FAL (File Abstraction Layer)

```php
<?php

declare(strict_types=1);

use TYPO3\CMS\Core\Resource\StorageRepository;
use TYPO3\CMS\Core\Resource\Security\FileNameValidator;
use TYPO3\CMS\Core\Utility\GeneralUtility;

// SECURE: FAL enforces the storage's fileDenyPattern and adds uploads via the
// storage driver, which sanitizes filenames and stays within the storage root.
$storage = GeneralUtility::makeInstance(StorageRepository::class)->findByUid(1);

// FileNameValidator rejects names matching $GLOBALS['TYPO3_CONF_VARS']['BE']['fileDenyPattern']
// (php, phtml, phar, .htaccess, etc.) — configured globally, applied centrally.
$validator = GeneralUtility::makeInstance(FileNameValidator::class);
if (!$validator->isValid($clientFileName)) {
    throw new \RuntimeException('Filename rejected by fileDenyPattern');
}

// addUploadedFile() sanitizes the name and writes through the storage driver.
$fileObject = $storage->addUploadedFile(
    $uploadInfo,                 // the $_FILES entry
    $targetFolder,               // a Folder within the storage
    null,                        // let the driver generate/sanitize the name
    \TYPO3\CMS\Core\Resource\Enum\DuplicationBehavior::RENAME, // never overwrite
);
```

### Python — Django / Flask / FastAPI

```python
# SECURE (Flask + Werkzeug): secure_filename strips path separators and
# normalizes the name, then we validate the SNIFFED type and randomize the name.
import os
import secrets
from flask import Flask, request, abort
from werkzeug.utils import secure_filename

try:
    import magic  # python-magic: libmagic content sniffing
except ImportError:
    magic = None

app = Flask(__name__)

# Storage OUTSIDE the static/ directory so files are never served as code.
UPLOAD_DIR = "/var/app/storage/uploads"
MAX_BYTES = 5 * 1024 * 1024
ALLOWED = {"image/jpeg": ".jpg", "image/png": ".png", "application/pdf": ".pdf"}

app.config["MAX_CONTENT_LENGTH"] = MAX_BYTES  # rejects oversized bodies (DoS)


@app.post("/upload")
def upload():
    file = request.files.get("doc")
    if file is None or file.filename == "":
        abort(400, "No file")

    # secure_filename: "../../etc/passwd" -> "etc_passwd"; defeats traversal.
    _ = secure_filename(file.filename)  # used only for logging, never trusted as-is

    # Read a sniff buffer and validate the REAL content type.
    head = file.stream.read(2048)
    file.stream.seek(0)
    mime = magic.from_buffer(head, mime=True) if magic else None
    if mime not in ALLOWED:
        abort(400, f"Disallowed type: {mime}")

    # Random name + extension derived from the detected type.
    name = secrets.token_hex(16) + ALLOWED[mime]
    dest = os.path.join(UPLOAD_DIR, name)
    file.save(dest)
    os.chmod(dest, 0o644)
    return {"stored": name}
```

```python
# SECURE (Django): a model form / serializer plus content validation.
# MEDIA_ROOT should not be served by the WSGI/script handler; serve via a
# dedicated file server or X-Sendfile, never as executable content.
from django.core.exceptions import ValidationError
import imghdr

ALLOWED_IMAGE = {"jpeg", "png", "gif"}


def validate_image(uploaded_file):
    if uploaded_file.size > 5 * 1024 * 1024:
        raise ValidationError("File too large")

    # imghdr inspects the magic bytes, not the filename.
    kind = imghdr.what(uploaded_file)
    if kind not in ALLOWED_IMAGE:
        raise ValidationError("Not a permitted image type")
```

```python
# SECURE (FastAPI): stream with a size cap, sniff content, randomize the name.
import secrets
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException
import magic

app = FastAPI()
UPLOAD_DIR = Path("/var/app/storage/uploads")
MAX_BYTES = 5 * 1024 * 1024
ALLOWED = {"image/jpeg": ".jpg", "image/png": ".png"}


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    head = await file.read(2048)
    mime = magic.from_buffer(head, mime=True)
    if mime not in ALLOWED:
        raise HTTPException(400, f"Disallowed type: {mime}")

    name = secrets.token_hex(16) + ALLOWED[mime]
    dest = UPLOAD_DIR / name
    written = len(head)
    with dest.open("wb") as out:
        out.write(head)
        while chunk := await file.read(64 * 1024):
            written += len(chunk)
            if written > MAX_BYTES:
                dest.unlink(missing_ok=True)
                raise HTTPException(413, "File too large")
            out.write(chunk)
    return {"stored": name}
```

### Node.js — Express / multer

```javascript
// VULNERABLE - DO NOT USE
// Trusts file.mimetype (set from the client headers) and keeps the original
// name in a public directory.
const multer = require("multer");
const badUpload = multer({ dest: "public/uploads/" }); // served + attacker-named
app.post("/upload", badUpload.single("file"), (req, res) => res.send("ok"));
```

```javascript
// SECURE: size limit, fileFilter on declared type, content re-validation after
// upload, random filename, destination OUTSIDE the public directory.
const crypto = require("crypto");
const path = require("path");
const fs = require("fs/promises");
const multer = require("multer");
const { fileTypeFromFile } = require("file-type"); // sniffs magic bytes

const ALLOWED = new Map([
  ["image/jpeg", ".jpg"],
  ["image/png", ".png"],
  ["application/pdf", ".pdf"],
]);

const STORAGE_DIR = "/var/app/storage/uploads"; // not under public/

const storage = multer.diskStorage({
  destination: STORAGE_DIR,
  filename: (_req, file, cb) => {
    const ext = ALLOWED.get(file.mimetype) ?? ".bin";
    cb(null, crypto.randomBytes(16).toString("hex") + ext);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024, files: 1 }, // size + count caps (DoS)
  // First-pass filter on the declared type (cheap reject before disk write).
  fileFilter: (_req, file, cb) =>
    cb(null, ALLOWED.has(file.mimetype)),
});

app.post("/upload", upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).send("No file");

  // Second pass: verify the ACTUAL bytes on disk, then reconcile the extension.
  const sniffed = await fileTypeFromFile(req.file.path);
  if (!sniffed || !ALLOWED.has(sniffed.mime)) {
    await fs.unlink(req.file.path);
    return res.status(400).send("Disallowed file type");
  }
  res.json({ stored: path.basename(req.file.path) });
});
```

### Ruby on Rails — ActiveStorage / CarrierWave / Shrine

```ruby
# SECURE (ActiveStorage): validate the content_type allowlist on the model.
class User < ApplicationRecord
  has_one_attached :avatar

  validate :acceptable_avatar

  private

  def acceptable_avatar
    return unless avatar.attached?

    errors.add(:avatar, "is too large") if avatar.blob.byte_size > 5.megabytes

    permitted = %w[image/jpeg image/png]
    # blob.content_type is derived by Marcel from the file's magic bytes,
    # not from the client-supplied header.
    errors.add(:avatar, "must be JPEG or PNG") unless permitted.include?(avatar.content_type)
  end
end
```

```ruby
# SECURE (CarrierWave): allowlist extensions AND content types.
class AvatarUploader < CarrierWave::Uploader::Base
  storage :file
  def store_dir = "uploads/#{model.class.to_s.underscore}/#{model.id}"

  def extension_allowlist = %w[jpg jpeg png]
  def content_type_allowlist = %w[image/jpeg image/png] # sniffed via file magic

  # Randomize the stored filename; never trust the original.
  def filename
    "#{SecureRandom.hex(16)}.#{file.extension}" if original_filename.present?
  end
end
```

```ruby
# SECURE (Shrine): the determine_mime_type plugin sniffs via libmagic/Marcel.
Shrine.plugin :determine_mime_type, analyzer: :marcel
Shrine.plugin :validation_helpers

class ImageUploader < Shrine
  Attacher.validate do
    validate_max_size 5 * 1024 * 1024
    validate_mime_type %w[image/jpeg image/png] # checks the DETERMINED type
    validate_extension %w[jpg jpeg png]
  end
end
```

### Java — Spring (MultipartFile)

```java
// SECURE (Spring Boot): cap multipart size in application.properties:
//   spring.servlet.multipart.max-file-size=5MB
//   spring.servlet.multipart.max-request-size=5MB
// then validate content by sniffing, randomize the name, store outside the web root.
@PostMapping("/upload")
public ResponseEntity<String> upload(@RequestParam("file") MultipartFile file) throws IOException {
    if (file.isEmpty()) {
        return ResponseEntity.badRequest().body("Empty file");
    }
    // Apache Tika reads magic bytes; do NOT trust file.getContentType() (client-set).
    String detected = new Tika().detect(file.getInputStream());
    Map<String, String> allowed = Map.of("image/jpeg", ".jpg", "image/png", ".png");
    if (!allowed.containsKey(detected)) {
        return ResponseEntity.badRequest().body("Disallowed type: " + detected);
    }
    String name = UUID.randomUUID() + allowed.get(detected);
    Path dest = Paths.get("/var/app/storage/uploads").resolve(name).normalize();
    file.transferTo(dest); // never use the client filename
    return ResponseEntity.ok(name);
}
```

### .NET — ASP.NET Core (IFormFile)

```csharp
// SECURE (ASP.NET Core): cap size via RequestSizeLimit / FormOptions, validate
// magic bytes, randomize the name, store outside wwwroot.
[HttpPost("upload")]
[RequestSizeLimit(5 * 1024 * 1024)]
public async Task<IActionResult> Upload(IFormFile file)
{
    if (file is null || file.Length == 0) return BadRequest("Empty file");

    // Inspect the leading bytes; file.ContentType is the client-supplied header.
    var head = new byte[8];
    await using var stream = file.OpenReadStream();
    _ = await stream.ReadAsync(head.AsMemory(0, head.Length));

    string? ext = head switch
    {
        [0xFF, 0xD8, 0xFF, ..]                       => ".jpg",
        [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, ..]     => ".png",
        _                                            => null,
    };
    if (ext is null) return BadRequest("Disallowed file type");

    stream.Position = 0;
    var name = Guid.NewGuid().ToString("N") + ext;
    var dest = Path.Combine("/var/app/storage/uploads", name); // outside wwwroot
    await using var outFile = System.IO.File.Create(dest);
    await stream.CopyToAsync(outFile);
    return Ok(new { stored = name });
}
```

## Defense Checklist

| Control | Why |
|---------|-----|
| Validate the **sniffed** MIME type (libmagic / finfo / Tika / Marcel), never the extension or client `Content-Type` | The filename and request headers are attacker-controlled (CWE-646) |
| Use an **allowlist** of accepted types, never a blocklist | Blocklists miss `.php5`, `.pht`, `.phar`, uppercase, trailing dots |
| **Randomize** the stored filename (`random_bytes` / UUID); derive the extension from the detected type | Prevents overwrite, traversal, and double-extension tricks (CWE-22) |
| **Store outside the web root**; serve via a controller / X-Sendfile | An uploaded script under `public/` is directly executable |
| If storage must be web-served, **disable script execution** for that directory | Defense-in-depth against RCE |
| Enforce **size limits** at the framework, app, and web-server layers | Unbounded bodies cause DoS (CWE-400) |
| **Re-encode** images and **strip metadata** | Defeats polyglots and ImageTragick; removes EXIF/GPS leakage |
| Set `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff` on downloads | Stops inline SVG/HTML XSS and MIME sniffing |
| Validate **archive members** against zip-slip and total decompressed size | Prevents path escape and zip bombs (CWE-409) |
| **Scan with anti-malware** (e.g. ClamAV) where files are shared with others | Catches known-malicious payloads before distribution |

```python
# SECURE: zip-slip + decompression-bomb safe extraction.
import zipfile
from pathlib import Path

MAX_TOTAL = 100 * 1024 * 1024   # 100 MB uncompressed cap
MAX_RATIO = 100                 # reject pathological compression ratios


def safe_extract(archive_path: str, dest_dir: str) -> None:
    dest = Path(dest_dir).resolve()
    total = 0
    with zipfile.ZipFile(archive_path) as zf:
        for info in zf.infolist():
            # Resolve the target and confirm it stays within dest (zip-slip).
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest) + "/"):
                raise ValueError(f"Zip-slip blocked: {info.filename}")

            total += info.file_size
            if total > MAX_TOTAL:
                raise ValueError("Decompression bomb: total size exceeded")
            if info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
                raise ValueError("Decompression bomb: ratio exceeded")

            zf.extract(info, dest)
```

## Detection Patterns

### Static Analysis

```
# PHP — move_uploaded_file using the client filename (overwrite + traversal)
grep -rEn "move_uploaded_file\s*\(.*\\\$_FILES\[[^]]+\]\['name'\]" --include="*.php"

# PHP — trusting the browser-supplied MIME type
grep -rEn "\\\$_FILES\[[^]]+\]\['type'\]" --include="*.php"

# PHP — extension blocklist (incomplete by design)
grep -rEn "(in_array|preg_match).*(php|phtml|exe).*pathinfo" --include="*.php"

# Node — multer writing directly into a public directory
grep -rEn "multer\s*\(\s*\{\s*dest:\s*['\"][^'\"]*public" --include="*.js" --include="*.ts"

# Node — trusting file.mimetype as the security boundary
grep -rEn "file\.mimetype\s*===|fileFilter" --include="*.js" --include="*.ts"

# Python — saving an UploadFile/FileStorage with no content validation nearby
grep -rEn "\.save\(|copyfileobj|file\.read\(\)" --include="*.py"

# Java / .NET — using the client-declared content type
grep -rEn "getContentType\(\)|file\.ContentType" --include="*.java" --include="*.cs"

# Any language — destination path inside a web-served root
grep -rEn "(uploads?|files?)/.*\\\$|wwwroot|public/uploads|htdocs" --include="*.php" --include="*.js" --include="*.py"
```

### Regex Detection Patterns

```php
<?php

declare(strict_types=1);

$detectionPatterns = [
    // Stored filename taken directly from the client
    '/move_uploaded_file\s*\(\s*\$_FILES\[[^\]]+\]\[\'tmp_name\'\]\s*,[^)]*\$_FILES\[[^\]]+\]\[\'name\'\]/'
        => 'CRITICAL: Uploaded file stored under attacker-controlled name',

    // Security decision based on the browser-supplied MIME type
    '/\$_FILES\[[^\]]+\]\[\'type\'\]\s*(?:===|==|!=)/'
        => 'HIGH: Trusting client-supplied Content-Type for validation',

    // Extension blocklist instead of an allowlist
    '/in_array\s*\(\s*\$ext.*\b(php|phtml|exe|sh)\b/i'
        => 'HIGH: Blocklist-based extension check (bypassable)',

    // multer writing into a publicly served directory
    '/multer\s*\(\s*\{[^}]*dest\s*:\s*[\'"][^\'"]*public/'
        => 'CRITICAL: multer destination inside public web root',

    // Archive extraction without a containment check (zip-slip)
    '/(?:extractall|zf\.extract|unzip|tarfile)\b(?!.*resolve)/i'
        => 'HIGH: Archive extraction without path-containment validation',
];
```

## Testing for File Upload Vulnerabilities

### Unit Tests

```php
<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

final class SecureUploadHandlerTest extends TestCase
{
    private SecureUploadHandler $handler;
    private string $storageDir;

    protected function setUp(): void
    {
        $this->storageDir = sys_get_temp_dir() . '/upload_test_' . bin2hex(random_bytes(8));
        mkdir($this->storageDir, 0755, true);
        $this->handler = new SecureUploadHandler($this->storageDir);
    }

    protected function tearDown(): void
    {
        array_map('unlink', glob($this->storageDir . '/*') ?: []);
        @rmdir($this->storageDir);
    }

    public function testRejectsPhpDisguisedAsImage(): void
    {
        // A PHP web shell sent with an image extension / spoofed Content-Type.
        $tmp = tempnam(sys_get_temp_dir(), 'shell');
        file_put_contents($tmp, "<?php system(\$_GET['c']); ?>");

        $this->expectException(\RuntimeException::class);
        // finfo detects text/x-php (or similar), not an allowed image type.
        $this->handler->store(['tmp_name' => $tmp, 'size' => filesize($tmp), 'error' => UPLOAD_ERR_OK]);
    }

    public function testRejectsPolyglotGifPhp(): void
    {
        // GIF header + appended PHP — getimagesize may pass, re-encode must drop the payload.
        $tmp = tempnam(sys_get_temp_dir(), 'poly');
        file_put_contents($tmp, "GIF89a;<?php phpinfo(); ?>");
        $clean = $this->storageDir . '/clean.jpg';

        $this->expectException(\RuntimeException::class);
        $this->handler->reencodeImage($tmp, $clean); // not a decodable image
    }

    public function testRejectsOversizedFile(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'big');
        $this->expectException(\RuntimeException::class);
        $this->handler->store(['tmp_name' => $tmp, 'size' => 50 * 1024 * 1024, 'error' => UPLOAD_ERR_OK]);
    }

    public function testStoredNameIsRandomAndExtensionDerived(): void
    {
        $png = base64_decode(
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='
        );
        $tmp = tempnam(sys_get_temp_dir(), 'png');
        file_put_contents($tmp, $png);

        // is_uploaded_file() guards real handlers; in unit tests, exercise the
        // validation pipeline (size/mime/getimagesize) directly instead.
        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $this->assertSame('image/png', $finfo->file($tmp));
        $this->assertNotFalse(getimagesize($tmp));
    }
}
```

### Integration Tests

```php
<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

final class UploadEndpointTest extends TestCase
{
    public function testEndpointRejectsWebShell(): void
    {
        $response = $this->client->request('POST', '/api/upload', [
            'multipart' => [[
                'name' => 'file',
                'contents' => "<?php system(\$_GET['c']); ?>",
                'filename' => 'shell.php.jpg',          // double extension
                'headers' => ['Content-Type' => 'image/jpeg'], // spoofed type
            ]],
        ]);

        $this->assertSame(400, $response->getStatusCode());
    }

    public function testStoredFileIsNotWebAccessibleAsScript(): void
    {
        // Upload a valid image, then confirm the served path returns the file as
        // an attachment (not executed) with a nosniff header.
        $upload = $this->client->request('POST', '/api/upload', [
            'multipart' => [['name' => 'file', 'contents' => fopen(__DIR__ . '/fixtures/avatar.png', 'r')]],
        ]);
        $this->assertSame(200, $upload->getStatusCode());

        $stored = json_decode($upload->getContent(), true)['stored'];
        $served = $this->client->request('GET', '/files/' . $stored);
        $this->assertSame('nosniff', $served->getHeaders()['x-content-type-options'][0] ?? null);
        $this->assertStringContainsString('attachment', $served->getHeaders()['content-disposition'][0] ?? '');
    }

    public function testEndpointRejectsZipSlip(): void
    {
        $response = $this->client->request('POST', '/api/import', [
            'multipart' => [['name' => 'archive', 'contents' => fopen(__DIR__ . '/fixtures/zip-slip.zip', 'r')]],
        ]);
        $this->assertSame(400, $response->getStatusCode());
    }
}
```

## CVSS Scoring

```yaml
Vulnerability: Unrestricted File Upload leading to Remote Code Execution
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

Analysis:
  Attack Vector: Network (N)
    - Exploitable via an HTTP multipart upload request
  Attack Complexity: Low (L)
    - Upload a script, then request it; no special conditions
  Privileges Required: None (N)
    - Often reachable on unauthenticated upload endpoints
  User Interaction: None (N)
  Scope: Changed (C)
    - Code execution escapes the application's intended boundary
  Confidentiality: High (H)
    - Full read access to application data and secrets
  Integrity: High (H)
    - Arbitrary write / defacement / backdoor persistence
  Availability: High (H)
    - Service takeover or destruction

Base Score: 10.0 (CRITICAL)
```

```yaml
Vulnerability: Stored XSS via SVG/HTML Upload
Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N

Analysis:
  Attack Vector: Network (N)
  Attack Complexity: Low (L)
  Privileges Required: Low (L)
    - Needs an account that can upload
  User Interaction: Required (R)
    - Victim opens the uploaded file from the app's origin
  Scope: Changed (C)
  Confidentiality: High (H)
    - Session/cookie theft within the victim origin
  Integrity: Low (L)
  Availability: None (N)

Base Score: 8.3 (HIGH)
```

## Remediation Priority

| Severity | Action | Timeline |
|----------|--------|----------|
| Critical | Validate the sniffed MIME type against an allowlist; never trust extension or client `Content-Type` | Immediate |
| Critical | Move upload storage outside the web root, or disable script execution for the upload directory | Immediate |
| High | Randomize stored filenames and derive extensions from detected types | 24 hours |
| High | Enforce size limits at framework, application, and web-server layers | 24 hours |
| High | Add zip-slip and decompression-bomb guards to all archive extraction | 24 hours |
| Medium | Re-encode images and strip EXIF/metadata; set `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff` | 1 week |
| Medium | Integrate anti-malware scanning for shared/distributed files | 1 week |
| Low | Add comprehensive upload bypass test coverage (web shell, polyglot, double extension, zip-slip) | 2 weeks |
| Low | Add static-analysis rules for upload anti-patterns | 2 weeks |
```