# Insecure Deserialization Prevention

## Understanding Insecure Deserialization (CWE-502)

### What Is Insecure Deserialization?

Serialization converts an in-memory object into a byte stream (or text) so it can be stored or transmitted; deserialization reverses the process. Insecure deserialization (CWE-502) occurs when an application reconstructs objects from untrusted data without restricting which classes may be instantiated or which side effects may run during reconstruction. Because many serialization formats encode the *type* of the object alongside its data, an attacker who controls the byte stream can force the application to instantiate arbitrary classes and invoke their lifecycle methods.

This maps to **OWASP A08:2021 — Software and Data Integrity Failures**. It was previously its own category, **A08:2017 — Insecure Deserialization**.

### Attack Concepts

- **Object injection** — The attacker supplies a serialized payload that instantiates classes the developer never intended to deserialize at that point, smuggling unexpected objects into the application's control flow.
- **Gadget chains** — The instantiated objects (gadgets) are already present in the application or its dependencies. The attacker chains their lifecycle methods together so that, on their own benign-looking, they combine into a primitive such as arbitrary file write or command execution. Tooling like `ysoserial` (Java) and `phpggc` (PHP) ships ready-made chains for popular libraries.
- **Magic methods** — Languages auto-invoke certain methods during/after deserialization. In PHP: `__wakeup()`, `__destruct()`, `__toString()`, `__call()`. In Python: `__reduce__`, `__setstate__`. These run *without* the developer explicitly calling them, which is what turns deserialization into code execution.
- **Remote Code Execution (RCE)** — The end goal of most gadget chains: trigger `system()`, `Runtime.exec`, `os.system`, template evaluation, or reflective method invocation.
- **Denial of Service (DoS)** — Deeply nested or self-referential payloads (a "billion laughs" analogue) exhaust CPU/memory during reconstruction even when no gadget is present.

### General Defenses (Apply Everywhere)

```
1. Do not deserialize untrusted data with native binary/object formats. Prefer data-only
   formats (JSON, well-defined Protobuf) that do not carry executable type information.
2. If native serialization is unavoidable, enforce an allowlist of permitted classes.
3. Sign serialized payloads with an HMAC and verify before deserializing (integrity).
4. Run deserialization in a low-privilege, sandboxed context.
5. Add depth/size limits to defend against DoS.
```

## Vulnerable and Secure Patterns by Language

### PHP

```php
<?php

declare(strict_types=1);

// VULNERABLE - DO NOT USE
// unserialize() on untrusted input instantiates ANY class and fires __wakeup()/__destruct()
$user = unserialize($_COOKIE['session']);
// Attacker supplies a phpggc-generated payload (e.g. Monolog/Laravel gadget) -> RCE

// VULNERABLE - DO NOT USE
// phar:// deserialization: file operations on attacker-controlled paths trigger
// unserialize() on the Phar metadata, even without an explicit unserialize() call.
$size = filesize('phar://' . $_GET['upload']);  // metadata is deserialized here
// Affected sinks: file_exists, is_file, fopen, getimagesize, file_get_contents, etc.
```

```php
<?php

declare(strict_types=1);

// SECURE: Disallow all classes — objects become __PHP_Incomplete_Class, no magic methods run
$data = unserialize($raw, ['allowed_classes' => false]);

// SECURE: Restrict to a strict allowlist when objects are genuinely required
$data = unserialize($raw, ['allowed_classes' => [Money::class, Address::class]]);

// PREFERRED: Use a data-only format for any untrusted boundary
$payload = json_decode($raw, associative: true, flags: JSON_THROW_ON_ERROR);

// SECURE: Sign payloads you produced yourself before trusting them again
final class SignedSerializer
{
    public function __construct(private readonly string $key) {}

    public function pack(array $data): string
    {
        $body = json_encode($data, JSON_THROW_ON_ERROR);
        $mac  = hash_hmac('sha256', $body, $this->key);
        return $mac . '.' . base64_encode($body);
    }

    public function unpack(string $token): array
    {
        [$mac, $b64] = explode('.', $token, 2) + [null, null];
        $body = base64_decode((string) $b64, true);
        if ($body === false || !hash_equals(hash_hmac('sha256', $body, $this->key), (string) $mac)) {
            throw new \RuntimeException('Tampered payload');
        }
        return json_decode($body, true, flags: JSON_THROW_ON_ERROR);
    }
}
```

**Phar mitigation:** in PHP < 8.0 set `phar.readonly = On` and validate that file paths never begin with `phar://`. From PHP 8.0 the Phar metadata is not unserialized on read, but allowlisting the scheme on user input remains best practice (see `path-traversal-prevention.md`).

### Python

```python
# VULNERABLE - DO NOT USE
# pickle executes __reduce__ during load -> arbitrary code execution
import pickle
obj = pickle.loads(request.data)        # attacker payload -> RCE

# VULNERABLE - DO NOT USE
# yaml.load with the default/Full loader constructs arbitrary Python objects
import yaml
config = yaml.load(user_input)          # !!python/object/apply:os.system ['id'] -> RCE
config = yaml.load(user_input, Loader=yaml.Loader)  # also unsafe

# VULNERABLE - DO NOT USE
# marshal is undocumented, version-specific, and unsafe on untrusted bytes
import marshal
data = marshal.loads(blob)
```

```python
# SECURE: prefer JSON for untrusted data — it cannot instantiate objects
import json
obj = json.loads(request.data)

# SECURE: yaml.safe_load only constructs plain scalars/lists/dicts
import yaml
config = yaml.safe_load(user_input)
# Equivalent explicit form:
config = yaml.load(user_input, Loader=yaml.SafeLoader)

# SECURE: if you must accept pickle from a trusted producer, authenticate it first
import hmac, hashlib, pickle

def loads_signed(token: bytes, key: bytes):
    mac, body = token[:32], token[32:]
    expected = hmac.new(key, body, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("Tampered payload")
    return pickle.loads(body)   # only reached for payloads we signed ourselves
```

A `pickle.Unpickler` subclass that overrides `find_class()` to reject everything is an additional hardening layer, but signing or avoiding pickle entirely is stronger.

### Java

```java
// VULNERABLE - DO NOT USE
// readObject() reconstructs any Serializable class on the classpath.
// ysoserial gadget chains (CommonsCollections, Spring, etc.) -> RCE
ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
MyDto dto = (MyDto) in.readObject();
```

```java
// SECURE: JEP 290 serialization filters (Java 9+) — allowlist by pattern, then deny the rest
import java.io.ObjectInputFilter;

ObjectInputStream in = new ObjectInputStream(input);
in.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
        "com.example.dto.*;java.lang.*;!*"));   // allow DTOs + java.lang, reject everything else
MyDto dto = (MyDto) in.readObject();

// A global JVM-wide filter can also be set:
//   -Djdk.serialFilter=maxdepth=10;maxarray=1000;com.example.**;!*
```

```java
// SECURE: look-ahead deserialization with a hard allowlist (pre-Java-9 or extra defense)
final class AllowlistObjectInputStream extends ObjectInputStream {
    private static final Set<String> ALLOWED = Set.of(
            "com.example.dto.MyDto", "java.util.ArrayList");

    AllowlistObjectInputStream(InputStream in) throws IOException { super(in); }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!ALLOWED.contains(desc.getName())) {
            throw new InvalidClassException("Blocked deserialization of: " + desc.getName());
        }
        return super.resolveClass(desc);
    }
}
```

```java
// PREFERRED: avoid native serialization entirely — use JSON with polymorphic typing OFF
import com.fasterxml.jackson.databind.ObjectMapper;

ObjectMapper mapper = new ObjectMapper();
// Default typing is OFF in Jackson 2.10+. NEVER re-enable it for untrusted input:
//   mapper.enableDefaultTyping();                 // <-- VULNERABLE, do not use
//   mapper.activateDefaultTyping(validator, ...); // <-- only with a strict PolymorphicTypeValidator
MyDto dto = mapper.readValue(json, MyDto.class);
```

### Ruby

```ruby
# VULNERABLE - DO NOT USE
# Marshal.load reconstructs arbitrary objects -> gadget chains -> RCE
obj = Marshal.load(params[:state])

# VULNERABLE - DO NOT USE
# YAML.load / Psych.load (before Psych 4 / Ruby 3.1) instantiate arbitrary classes
require 'yaml'
config = YAML.load(user_input)          # !ruby/object:... -> object injection
config = Psych.load(user_input)
```

```ruby
# SECURE: safe_load only permits a small allowlist of scalar/collection types
require 'yaml'
config = YAML.safe_load(user_input)

# SECURE: explicitly permit the classes you actually need
config = YAML.safe_load(user_input, permitted_classes: [Date, Symbol], aliases: false)

# In Ruby 3.1+ / Psych 4, YAML.load IS safe by default (delegates to safe_load);
# use YAML.unsafe_load only for fully trusted input.

# PREFERRED: use JSON for any untrusted boundary
require 'json'
data = JSON.parse(user_input)
```

### .NET

```csharp
// VULNERABLE - DO NOT USE
// BinaryFormatter is obsolete and dangerous; disabled by default in .NET 5+ and
// removed from the runtime in .NET 9. TypeConfuseDelegate gadget -> RCE.
var formatter = new BinaryFormatter();
var obj = formatter.Deserialize(stream);

// VULNERABLE - DO NOT USE
// Json.NET with TypeNameHandling != None lets the payload pick the CLR type to instantiate.
var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
var obj = JsonConvert.DeserializeObject<object>(json, settings);  // $type -> arbitrary type -> RCE
```

```csharp
// SECURE: System.Text.Json — no polymorphic type resolution from the payload by default
using System.Text.Json;
var dto = JsonSerializer.Deserialize<MyDto>(json);

// SECURE: Json.NET with TypeNameHandling.None (the default) and a concrete target type
var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };
var dto = JsonConvert.DeserializeObject<MyDto>(json, settings);

// SECURE: if polymorphism is unavoidable, bind types through a strict SerializationBinder
var settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.Auto,
    SerializationBinder = new AllowlistBinder()   // resolves only known, safe types
};
```

### Node.js

```javascript
// VULNERABLE - DO NOT USE
// node-serialize evaluates "_$$ND_FUNC$$_" immediately-invoked functions on unserialize
const serialize = require('node-serialize');
const obj = serialize.unserialize(req.cookies.profile);
// {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"} -> RCE

// VULNERABLE - DO NOT USE
// funcster reconstructs functions from serialized source via the Function constructor
const funcster = require('funcster');
const fn = funcster.deepDeserialize(untrusted);

// VULNERABLE - DO NOT USE
// JSON.parse reviver that resurrects behaviour or merges into prototypes
const obj = JSON.parse(body, (key, value) => {
  if (key === '__proto__') return value;          // enables prototype pollution
  return value;
});
```

```javascript
// SECURE: plain JSON.parse with no reviver only ever yields data, never behaviour
const obj = JSON.parse(body);

// SECURE: drop dangerous keys defensively to block prototype pollution adjacency
function safeParse(body) {
  return JSON.parse(body, (key, value) => {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      return undefined;
    }
    return value;
  });
}

// SECURE: validate the parsed shape against a schema before use (zod/ajv/joi)
import { z } from 'zod';
const Profile = z.object({ id: z.number(), name: z.string() }).strict();
const profile = Profile.parse(JSON.parse(body));   // throws on unexpected keys/types
```

**Prototype pollution adjacency:** deserialization that merges attacker keys (`__proto__`, `constructor.prototype`) into objects can poison `Object.prototype` globally, leading to property injection, DoS, or RCE in downstream sinks. Use `Object.create(null)`, `Map`, or freeze the prototype, and reject the reserved keys above.

## Framework Notes

### Laravel / Symfony / TYPO3 (PHP)

```php
<?php

declare(strict_types=1);

// Laravel: signed cookies/sessions are HMAC-verified, but custom code that pulls
// raw values and unserializes them bypasses that protection.
// VULNERABLE:
$state = unserialize(request()->input('state'));
// SECURE: keep state in the signed session, or json_decode explicit fields.

// Symfony: the Serializer XML/CSV encoders are data-only and safe. Avoid the
// deprecated PhpSerializer for any untrusted boundary; configure the Messenger
// transport with the (default) Symfony Serializer rather than php_serialize.
//   framework:
//       messenger:
//           serializer:
//               default_serializer: messenger.transport.symfony_serializer

// TYPO3: never unserialize() request data. Historically TYPO3 used serialized
// values in some persisted fields — when reading those, pass allowed_classes:
$value = unserialize($row['config'], ['allowed_classes' => false]);
```

### Rails (Ruby)

```ruby
# Rails encrypts and signs cookies/sessions by default; do not switch the
# session store back to Marshal over unsigned data.
#
# ActiveRecord `serialize` should pin a coder and (for YAML) permitted classes:
class Setting < ApplicationRecord
  # SECURE: JSON coder cannot instantiate arbitrary objects
  serialize :preferences, coder: JSON
end
# If YAML is required, configure the app to restrict permitted classes:
#   config.active_record.yaml_column_permitted_classes = [Symbol, Date]
```

### Django (Python)

```python
# Django signed cookies use JSON by default. NEVER set the session serializer to
# PickleSerializer — a leaked SECRET_KEY would then escalate to RCE.
# settings.py
SESSION_SERIALIZER = "django.contrib.sessions.serializers.JSONSerializer"  # default, keep it

# Cache: avoid the pickle-based backends for any cache that crosses a trust
# boundary or could be written by an attacker (e.g. a shared/unauthenticated Redis).
```

## Detection Patterns

These regex patterns are suitable for `grep`/`ripgrep` and mirror how `checkpoints.yaml` patterns work. Tune per language with `--include`/`-g` globs.

```bash
# PHP — unserialize() without an allowed_classes allowlist, and phar:// sinks
rg -n "unserialize\s*\(" --glob '*.php' | rg -v "allowed_classes"
rg -n "(filesize|file_exists|is_file|fopen|file_get_contents|getimagesize)\s*\(\s*['\"]phar://" --glob '*.php'

# Python — pickle/marshal loads and unsafe yaml.load
rg -n "\b(pickle|cPickle)\.(loads?)\s*\(" --glob '*.py'
rg -n "\bmarshal\.loads?\s*\(" --glob '*.py'
rg -n "yaml\.load\s*\(" --glob '*.py' | rg -v "SafeLoader|safe_load"

# Java — native object input and re-enabled default typing
rg -n "new\s+ObjectInputStream|\.readObject\s*\(" --glob '*.java'
rg -n "enableDefaultTyping|activateDefaultTyping" --glob '*.java'

# Ruby — Marshal.load and unsafe YAML/Psych loaders
rg -n "Marshal\.load\b" --glob '*.rb'
rg -n "(YAML|Psych)\.(load|unsafe_load)\b" --glob '*.rb' | rg -v "safe_load"

# .NET — BinaryFormatter and Json.NET TypeNameHandling
rg -n "BinaryFormatter|NetDataContractSerializer|LosFormatter|SoapFormatter" --glob '*.cs'
rg -n "TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects|Arrays)" --glob '*.cs'

# Node.js — known unsafe (un)serializers and prototype-polluting revivers
rg -n "node-serialize|funcster|serialize-to-js" --glob '*.{js,ts}'
rg -n "\.unserialize\s*\(|deepDeserialize\s*\(" --glob '*.{js,ts}'
rg -n "__proto__|constructor\s*\[\s*['\"]prototype" --glob '*.{js,ts}'
```

### Severity Mapping

```yaml
patterns:
  - id: php-unserialize-untrusted
    regex: "unserialize\\s*\\((?!.*allowed_classes)"
    severity: CRITICAL
    note: "unserialize() without allowed_classes on potentially untrusted input -> object injection / RCE"
  - id: python-pickle-loads
    regex: "\\b(pickle|cPickle)\\.loads?\\s*\\("
    severity: CRITICAL
    note: "pickle.loads on untrusted data executes __reduce__ -> RCE"
  - id: python-yaml-load
    regex: "yaml\\.load\\s*\\((?!.*Safe)"
    severity: HIGH
    note: "yaml.load without SafeLoader constructs arbitrary objects"
  - id: java-readobject
    regex: "\\.readObject\\s*\\("
    severity: HIGH
    note: "Native Java deserialization without a JEP 290 filter -> ysoserial gadget chains"
  - id: ruby-marshal-load
    regex: "Marshal\\.load\\b"
    severity: CRITICAL
    note: "Marshal.load on untrusted data -> object injection / RCE"
  - id: dotnet-binaryformatter
    regex: "BinaryFormatter"
    severity: CRITICAL
    note: "BinaryFormatter is obsolete and exploitable; migrate to System.Text.Json"
  - id: node-serialize
    regex: "node-serialize|funcster"
    severity: CRITICAL
    note: "node-serialize/funcster reconstruct functions from input -> RCE"
```

## Testing for Insecure Deserialization

### PHP (PHPUnit)

```php
<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;

final class DeserializationPreventionTest extends TestCase
{
    public function testAllowedClassesFalseBlocksObjectInstantiation(): void
    {
        // A serialized DateTime object
        $payload = serialize(new \DateTime('2026-01-01'));

        $result = unserialize($payload, ['allowed_classes' => false]);

        // With allowed_classes => false the object becomes __PHP_Incomplete_Class,
        // so no magic methods fire and the gadget cannot run.
        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $result);
    }

    public function testSignedSerializerRejectsTamperedPayload(): void
    {
        $serializer = new \SignedSerializer('secret-key');
        $token = $serializer->pack(['user_id' => 1]);

        // Flip a byte in the body
        $tampered = substr($token, 0, -4) . 'AAAA';

        $this->expectException(\RuntimeException::class);
        $serializer->unpack($tampered);
    }

    public function testRejectsPharScheme(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        // Whatever wrapper rejects user-supplied phar:// paths
        (new \FileScheme())->assertSafe('phar:///tmp/evil.phar/x');
    }
}
```

### Python (pytest)

```python
import json
import pytest
import yaml


def test_safe_load_does_not_instantiate_objects():
    payload = "!!python/object/apply:os.system ['echo pwned']"
    # safe_load refuses the python/object tag instead of executing it
    with pytest.raises(yaml.YAMLError):
        yaml.safe_load(payload)


def test_json_parse_yields_only_data():
    obj = json.loads('{"role": "admin", "id": 1}')
    assert isinstance(obj, dict)
    assert obj["role"] == "admin"


def test_signed_pickle_rejects_tampered_payload(signed_loader, secret):
    token = bytearray(signed_loader.dumps({"id": 1}))
    token[-1] ^= 0xFF  # corrupt the body
    with pytest.raises(ValueError):
        signed_loader.loads(bytes(token))
```

### Java (JUnit)

```java
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.InvalidClassException;
import org.junit.jupiter.api.Test;

class DeserializationFilterTest {

    @Test
    void blocksDisallowedClass() {
        // A serialized payload whose class is not on the allowlist must be rejected
        // before any gadget can be reconstructed.
        assertThrows(InvalidClassException.class, () ->
                AllowlistObjectInputStream.readFrom(maliciousGadgetBytes()));
    }

    @Test
    void allowsExpectedDto() throws Exception {
        MyDto dto = AllowlistObjectInputStream.readFrom(serialize(new MyDto(1, "ok")));
        org.junit.jupiter.api.Assertions.assertEquals(1, dto.id());
    }
}
```

### Integration Test (HTTP boundary, language-agnostic)

```php
<?php

declare(strict_types=1);

public function testSessionEndpointRejectsForgedObjectPayload(): void
{
    // phpggc-style gadget for the app's dependency set, base64-encoded into a cookie
    $gadget = base64_encode('O:8:"Evil":0:{}');

    $response = $this->client->request('GET', '/account', [
        'headers' => ['Cookie' => 'session=' . $gadget],
    ]);

    // The forged object must never be instantiated; expect a clean rejection,
    // not a 500 (which often signals the gadget partially executed).
    $this->assertSame(400, $response->getStatusCode());
    $this->assertStringNotContainsString('uid=', $response->getContent());
}
```

## CVSS Scoring

```yaml
Vulnerability: Insecure Deserialization - Remote Code Execution
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

Analysis:
  Attack Vector: Network (N)
    - Payload delivered via cookie, request body, or message queue
  Attack Complexity: Low (L)
    - Public gadget chains (ysoserial, phpggc) require no novel research
  Privileges Required: None (N)
    - Often reachable pre-authentication (session cookies, import endpoints)
  User Interaction: None (N)
  Scope: Changed (C)
    - RCE escapes the application's security context
  Confidentiality: High (H)
  Integrity: High (H)
  Availability: High (H)

Base Score: 10.0 (CRITICAL)
```

```yaml
Vulnerability: Insecure Deserialization - Denial of Service
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

Analysis:
  Attack Vector: Network (N)
  Attack Complexity: Low (L)
  Privileges Required: None (N)
  User Interaction: None (N)
  Scope: Unchanged (U)
  Confidentiality: None (N)
  Integrity: None (N)
  Availability: High (H)
    - Nested/self-referential payload exhausts CPU or memory

Base Score: 7.5 (HIGH)
```

## Remediation Priority

| Severity | Action | Timeline |
|----------|--------|----------|
| Critical | Stop deserializing untrusted data with `unserialize`/`pickle`/`Marshal.load`/`readObject`/`BinaryFormatter`; switch to JSON or another data-only format | Immediate |
| Critical | Disable `node-serialize`/`funcster` and Json.NET `TypeNameHandling`/Jackson default typing on untrusted input | Immediate |
| High | Apply class allowlists: PHP `allowed_classes`, Java JEP 290 filters, Ruby `permitted_classes`, .NET `SerializationBinder` | 24 hours |
| High | HMAC-sign and verify any serialized payload the application itself produced before re-trusting it | 24 hours |
| Medium | Reject `phar://` schemes and prototype-polluting keys (`__proto__`, `constructor`, `prototype`) on inputs | 1 week |
| Medium | Add depth/size limits to deserializers to mitigate DoS | 1 week |
| Low | Add static analysis rules and the detection patterns above to CI | 2 weeks |
| Low | Add gadget-chain and tampered-payload test coverage for every deserialization boundary | 2 weeks |
