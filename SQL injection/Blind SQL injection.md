# Blind SQL injection

> Use the information here only for systems you own or have explicit permission to test, and for learning/defensive validation.
> I’m not including copy-paste exploit payloads or step-by-step extraction sequences for real targets; the focus is on understanding the techniques and how to prevent them safely.
## What blind SQLi is
Blind SQL injection happens when an application is vulnerable to SQL injection, but its HTTP responses don’t include the query results or detailed database errors.
Because you can’t “see” the injected output directly, common visible techniques like `UNION`-based extraction are often ineffective. 

## Core exploitation signals (conceptual)
Blind SQLi is still exploitable when you can observe *some* external signal that changes based on a condition evaluated in the database, such as response content differences, error behavior, response time, or out-of-band interactions.
In practice, you use the application as an oracle: ask yes/no questions (boolean conditions) and infer answers from those signals. 

### 1) Conditional responses (boolean-based)
If the page behaves differently depending on whether a query returns rows (for example, a “Welcome back” message), you can infer whether an injected condition is true or false by watching that behavior change. 
PortSwigger’s example uses a tracking cookie value embedded into a SQL query, where toggling a boolean condition changes whether the app shows a “Welcome back” message. 
Common building blocks (DBMS-dependent):
- Boolean predicates: equality/inequality checks, comparisons, and `EXISTS(...)`-style checks. 
- String inspection: use a substring function to compare one character at a time (function name varies by DBMS).  

Substring naming reminder (same concept, different function names): 
- Oracle: `SUBSTR(...)` 
- Microsoft SQL Server / PostgreSQL / MySQL: `SUBSTRING(...)` 

### 2) Conditional errors (error-based inference)
If the app’s normal output doesn’t change with boolean logic, you can sometimes force a detectable difference by causing a database error only when a condition is true (for example, using `CASE WHEN ... THEN ... ELSE ... END`). 
PortSwigger describes using a conditional divide-by-zero pattern to trigger an error in one case and not the other, letting you infer the condition. 

DBMS-specific implementations vary, and the exact “best” error primitive depends on the platform and how errors are handled. 

### 3) Verbose error messages (turning “blind” into “visible”)
Misconfiguration can expose verbose SQL errors that reveal useful context, such as the query shape and where your input lands (for example, inside a single-quoted string in a `WHERE` clause). 
In some cases, you can also elicit errors that include (or strongly hint at) data values, for example by attempting an invalid cast like `CAST(<string> AS int)` and reading the resulting error message. 
### 4) Time delays (time-based inference)
If content and error behavior are stable (errors are caught/hidden), time-based techniques can still work by conditionally delaying query execution and measuring response time. 
This works best when the query is executed synchronously (delaying the DB delays the HTTP response), but the delay functions are DBMS-specific. 

Common delay primitives by DBMS (names differ): 
- Oracle: `dbms_pipe.receive_message(('a'),10)` 
- Microsoft SQL Server: `WAITFOR DELAY '0:0:10'` 
- PostgreSQL: `SELECT pg_sleep(10)` 
- MySQL: `SELECT SLEEP(10)` 

Conditional time-delay patterns also vary by DBMS (for example, `CASE WHEN (...) THEN <sleep> ELSE <no-sleep> END`-style constructs). 

### 5) Out-of-band (OAST) interactions
If the vulnerable SQL runs asynchronously (so response content, errors, and timing don’t reliably change), out-of-band techniques can help by triggering a network interaction that you can observe externally. 
PortSwigger highlights DNS as commonly effective in production environments due to permissive egress, and describes Burp Collaborator as a practical way to detect those interactions. 
OAST techniques are DBMS- and environment-specific and may require particular features, permissions, or network egress to succeed. 

## Prevention (same as “normal” SQLi)
Even though blind SQLi exploitation looks different, the prevention is the same: use parameterized queries (prepared statements) so untrusted input cannot change SQL structure. 
OWASP recommends prepared statements with variable binding as the primary defense, because the SQL code is defined first and parameters are passed separately. 
Avoid building SQL by string concatenation, and treat “stored in the database” data as untrusted if it can be influenced by users (to reduce second-order risks). 

Safe patterns (examples):
```java
// Java (JDBC)
String q = "SELECT account_balance FROM user_data WHERE user_name = ?";
PreparedStatement ps = connection.prepareStatement(q);
ps.setString(1, custname);
ResultSet rs = ps.executeQuery();
```


```php
// PHP (PDO)
$stmt = $dbh->prepare("INSERT INTO REGISTRY (name, value) VALUES (:name, :value)");
$stmt->bindParam(':name', $name);
$stmt->bindParam(':value', $value);
$stmt->execute();
```


Operational hardening that reduces impact if something slips through:
- Use least-privilege DB accounts so an injection can’t access or modify more than necessary. 
- Prefer query APIs/ORMs that parameterize by default, and add guardrails/code review checks to prevent ad-hoc dynamic SQL. 
