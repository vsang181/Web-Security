# Path traversal (directory traversal)

Path traversal is a vulnerability where an application lets attacker-controlled input influence a filesystem path, enabling read access to files outside the intended directory (and sometimes write access).  
Common impact includes exposure of application source/config, credentials/secrets, and sensitive OS files; if write is possible, this can escalate to code execution or full host compromise.

## How it happens
The usual root cause is building a path like `BASE_DIR + userInput` (or similar) and then reading it with a filesystem API without robust validation + normalization.  
Typical entry points include image/file download endpoints (`/download?file=...`), import/export features, log viewers, template/theme loaders, or any “load by filename” functionality.

Example (vulnerable pattern):
```text
GET /loadImage?filename=<userInput>
server: readFile("/var/www/images/" + userInput)
```

## Common traversal patterns (for defensive testing)
Traversal generally works by using “go up a directory” sequences and/or alternate path representations so the resolved path escapes the base directory.  
Exact behavior depends on OS, language runtime, and how many times the app/framework decodes/normalizes input.

Things to consider when reviewing a code path:
- Relative traversal sequences: `../` (Unix-like), `..\` (Windows).
- Absolute paths: inputs that start from filesystem root (Unix-like) or include drive letters (Windows) can bypass “strip `../`” style defenses.
- Encoding/decoding issues: URL-encoded separators and dot sequences may be normalized by proxies/frameworks before your code sees them; double-decoding bugs can reintroduce traversal after “sanitization.”
- Normalization tricks: repeated separators, mixed slashes, and odd dot patterns can behave differently across platforms and libraries.
- Prefix/suffix validation pitfalls: checks like “must start with `/var/www/images`” or “must end with `.png`” are often bypassed if you validate the raw string rather than the canonical resolved path.
- Null byte edge cases: older stacks (and some native bindings) historically had issues where `%00` could terminate strings and bypass extension checks; modern frameworks often mitigate this, but legacy code still shows up.

Safe review mindset: assume any string-based filtering (`replace("../","")`, regex bans, “strip slashes”) will eventually be bypassed unless you also canonicalize and enforce containment.

## Common obstacles (and what they imply)
Applications often add partial defenses that reduce obvious traversal but still leave gaps:
- “Strip `../`” once: if stripping is non-recursive, nested sequences can collapse back into traversal after the first pass.
- “Decode then validate” vs “validate then decode”: the order matters; validate the exact representation you will use for filesystem access (after all decoding/normalization).
- “Only allow within base dir”: this is good, but it must be implemented using canonical paths and must account for symlinks if attackers can influence files within the base directory.

If you can’t reason confidently about the full normalization pipeline (reverse proxy → framework routing → request parser → your code), treat the endpoint as high risk until proven otherwise.

## How to prevent path traversal
Best: don’t accept filenames/paths from users at all; use indirect references (IDs) mapped to server-known paths (e.g., DB lookup), or store files in object storage with signed URLs.  
If you must accept user input that influences a path, use two layers: strict input validation (prefer allow-lists) and canonicalization + base-directory containment checks.

### 1) Prefer allow-lists (indirect object reference)
Instead of:
```text
GET /download?file=invoice-2026-02.pdf
```

Do:
```text
GET /download?id=2f3c1a...
server: lookup id -> exact stored path (not user-controlled)
```

### 2) Canonicalize and enforce containment
Java example (canonical path enforcement):
```java
File file = new File(BASE_DIRECTORY, userInput);
if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {
    // process file
}
```

Stronger variants you should consider in real code:
- Reject path separators and dot segments in `userInput` entirely if your use-case only needs “simple names” (e.g., `218.png`).
- Use `Path` APIs rather than string concatenation, then normalize/resolve:
  - Java: `Paths.get(BASE).resolve(userInput).normalize()`
  - Node.js: `path.resolve(BASE, userInput)` (then check prefix)
  - Python: `Path(BASE, userInput).resolve()` (then check containment)
  - .NET: `Path.GetFullPath(Path.Combine(BASE, userInput))` (then check prefix)

Node.js example (containment check):
```js
import path from "path";
import fs from "fs/promises";

const BASE = "/var/www/images";

function isWithinBase(base, target) {
  const rel = path.relative(base, target);
  return rel && !rel.startsWith("..") && !path.isAbsolute(rel);
}

export async function loadImage(filename) {
  // Optionally enforce strict allow-list: /^[A-Za-z0-9_.-]+$/
  const fullPath = path.resolve(BASE, filename);

  if (!isWithinBase(BASE, fullPath)) {
    throw new Error("Invalid path");
  }

  return await fs.readFile(fullPath);
}
```

Python example (Pathlib):
```python
from pathlib import Path

BASE = Path("/var/www/images").resolve()

def load_image(filename: str) -> bytes:
    # Optionally allow-list: only simple filenames
    full_path = (BASE / filename).resolve()

    if BASE not in full_path.parents and full_path != BASE:
        raise ValueError("Invalid path")

    return full_path.read_bytes()
```

### 3) Reduce blast radius
Even with good validation, assume something will go wrong eventually:
- Run the app with least-privilege OS permissions; the process should not be able to read secrets it doesn’t need.
- Segregate uploaded/user-controlled files from application code/config directories.
- Consider container isolation and read-only filesystem mounts where practical.
- Treat “write paths” (uploads, exports, caches) as high-risk and restrict locations + file types strictly.

### 4) Don’t forget symlinks
If attackers can create or influence files inside the allowed directory, symlinks can redirect “safe-looking” paths to sensitive locations.  
Mitigations include disallowing symlinks in served directories, storing files outside web root with controlled access, or using platform-specific safe-open patterns where you open relative to a directory handle and reject symlink traversal.
