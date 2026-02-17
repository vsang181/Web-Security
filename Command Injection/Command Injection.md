# OS command injection (shell injection)

OS command injection (aka *shell injection*) occurs when an application builds an operating system command using attacker-influenced input and executes it via a shell, allowing the attacker to run unintended commands on the server.  
This often leads to full compromise of the application and its data, and can be used to pivot into other internal systems depending on privileges and network trust.

## How it happens (typical pattern)
A common root cause is string-building a command like:

```text
stockreport.pl <productId> <storeId>
```

If `productId`/`storeId` are not strictly validated and are inserted into the command line, shell parsing can treat parts of the input as control characters (separators, pipes, redirects), changing what actually gets executed.

Two related problems:
- Shell injection: the shell interprets metacharacters in user input as syntax.
- Argument injection: even without metacharacters, user input can add/modify flags/options (for example, `--some-flag`) if the app doesn’t separate arguments safely.

## In-band vs blind command injection
Command injection comes in two main flavors:

### In-band (output returned)
The HTTP response includes command output (stdout/stderr), making detection and impact obvious.

### Blind (output not returned)
The command executes, but the application does not return output in the response.  
In blind cases, you typically only observe secondary effects, such as:
- A response-time change (time-based confirmation).
- A side-effect on the server (file written, state changed).
- An outbound interaction (DNS/HTTP) to a system you control in an authorized test environment.

## Shell metacharacters to be aware of
These characters/operators may be interpreted by shells and are commonly involved in command injection issues:

- Cross-platform separators/operators (often work on Windows and Unix-like shells): `&`, `&&`, `|`, `||`
- Unix-like only (common): `;`, newline (`\n`)
- Unix-like inline execution/substitution: `` `cmd` ``, `$(cmd)`

Quoted contexts matter. If user input lands inside quotes in the original command, an attacker may attempt to break out of that context before injecting operators, so treating “it’s in quotes” as protection is not sufficient.

## Useful system triage commands (authorized use)
After confirming a command injection issue in an approved environment, these commands are commonly used to quickly understand context:

| Purpose | Linux | Windows |
|---|---|---|
| Current user | `whoami` | `whoami` |
| OS details | `uname -a` | `ver` |
| Network config | `ifconfig` | `ipconfig /all` |
| Network connections | `netstat -an` | `netstat -an` |
| Running processes | `ps -ef` | `tasklist` |

## Prevention (what to implement)

## 1) Best fix: don’t call OS commands
In most cases you can replace shell calls with safer platform/library APIs (for example: filesystem, DNS, HTTP clients, image processing, PDF generation).  
Removing the shell boundary removes an entire class of injection risk.

## 2) If you must execute a process: avoid the shell and separate arguments
Do not build a single command string that a shell parses. Prefer APIs that accept an executable and an argument list.

Java (good)
```java
ProcessBuilder pb = new ProcessBuilder("stockreport.pl", productId, storeId);
Process p = pb.start();
```

Java (bad)
```java
ProcessBuilder pb = new ProcessBuilder("stockreport.pl " + productId + " " + storeId);
```

Node.js (prefer execFile/spawn; avoid exec with a single string)
```js
import { execFile } from "child_process";

execFile("stockreport.pl", [productId, storeId], (err, stdout, stderr) => {
  // handle output safely
});
```

Python (avoid shell=True; pass args as a list)
```python
import subprocess

subprocess.run(["stockreport.pl", product_id, store_id], check=True)
```

## 3) Strong input validation (allow-lists)
If user input influences command execution at all, validate *before* execution:

- Prefer allow-lists of permitted values (best when the input should be one of a known set).
- If the input must be numeric, enforce numeric-only (and bounds).
- If the input must be a simple token, enforce strict character sets and maximum length (reject whitespace and all shell metacharacters).

Example patterns (illustrative)
```text
Numeric-only: ^[0-9]{1,10}$
Token-only:   ^[A-Za-z0-9_-]{1,32}$
```

Never rely on “escaping shell metacharacters” as your primary defense. It’s brittle across shells/platforms/encodings and easy to get wrong.

## 4) Defend against option/argument injection
Even if you block separators, user input may still be interpreted as options/flags by the target program.

Mitigations:
- Don’t let users choose the executable.
- When supported, insert an end-of-options marker (`--`) before user-controlled values.
- Validate that user input cannot start with `-` if it should never be an option.
- Use fixed, server-side flags; only pass user input as data arguments.

## 5) Least privilege and containment
Assume prevention can fail and reduce blast radius:

- Run the app under a low-privilege OS account.
- Use dedicated service accounts for any helper process with narrowly scoped permissions.
- Restrict filesystem and network access (containers, sandboxing, AppArmor/SELinux, Windows job objects, outbound egress controls).
- Avoid placing secrets in locations readable by the web process.

## 6) Logging and monitoring
- Log execution attempts (what function was called, which safe executable, which request path), but do **not** log secrets or raw injection strings verbatim in a way that becomes a secondary vulnerability.
- Alert on anomalous behavior: repeated failures, unusual process spawning, spikes in execution time, unexpected outbound DNS/HTTP, or access to sensitive paths.
