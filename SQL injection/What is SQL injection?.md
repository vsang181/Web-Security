## SQL injection

In this section, we explain:
- What SQL injection (SQLi) is.
- How to find and exploit different types of SQLi vulnerabilities (from a defender/tester perspective, focusing on validation patterns and technical behaviors).
- How to prevent SQLi, following OWASP Cheat Sheet Series guidance (primary defenses + additional defenses). 

## What is SQL injection (SQLi)?

SQL injection (SQLi) is a class of injection flaw where an application sends **untrusted data** to a SQL interpreter in a way that allows the attacker to modify the intended database query. 
SQLi typically arises when applications build **dynamic SQL** via string concatenation using user-supplied input, so attacker-controlled characters can change the SQL syntax/logic rather than being treated as data. 

Technically, SQLi is best understood as a failure of **code/data separation**: SQL keywords/operators become reachable from data-plane input because the application composes query text unsafely. [stackoverflow]

## What is the impact of a successful SQL injection attack?

A successful SQL injection attack can:
- Read sensitive database data (credentials, personal data, financial data). 
- Modify data (insert/update/delete), affecting integrity and business logic outcomes. 
- Execute administrative DB operations in some configurations (e.g., DB shutdown), depending on privileges.   
- Read/write files on the DBMS host in some DBMS configurations, and in some cases issue operating system commands (highly dependent on DBMS features, configuration, and privileges). 

The practical impact is primarily driven by the **privileges** of the application’s DB account and by environmental controls (segmentation, outbound connectivity, OS-level privilege constraints). [stackoverflow]

## How to detect SQL injection vulnerabilities

You can detect SQLi via systematic testing and/or code review, but OWASP highlights that injection is easiest to discover by examining code and more difficult through testing alone; scanners/fuzzers can help find candidates. 

### During code review (most reliable)
Look for:
- Database queries **not using prepared statements/parameterized APIs**. 
- Any **dynamic SQL generation** (string building) that includes user-controlled data; verify whether it is safely handled (parameterization/allowlisting). 
- Stored procedures that use dynamic execution constructs (e.g., SQL Server `sp_execute`, `execute`, `exec`), because these often indicate dynamically composed SQL inside procedures. 

### During testing (behavioral validation)
Practical SQLi validation usually relies on finding a consistent “control knob” where changing input changes query semantics, then confirming repeatability. Techniques OWASP explicitly calls out include: 

- **Time delay exploitation**: In blind SQLi cases, inject a conditional that triggers a server-side sleep/delay if true, and infer truth from response timing (DBMS-specific functions differ).   
  Example pattern from OWASP (MySQL-style):  
  `http://www.example.com/product.php?id=10 AND IF(version() like '5%', sleep(10), 'false'))--`   

- **Out-of-band (OOB) exploitation**: In blind cases, use DBMS functions to make the server perform an external interaction and encode results in the callback (DBMS-specific).   

### Stored procedure injection (special note)
If a stored procedure builds dynamic SQL internally and user input is not properly sanitized, the stored procedure can still be vulnerable to SQLi. 

## SQL injection in different parts of the query

SQLi is not limited to a `WHERE` clause. Any place where attacker-controlled input is concatenated into SQL text can be an injection point, including:
- `INSERT` values
- `UPDATE` set clauses or predicates
- Dynamic identifiers (table/column names)
- Sorting logic (`ORDER BY`, including `ASC/DESC`) 

OWASP calls out that some query parts are **not legal locations for bind variables** (e.g., table/column names and sort order), which is why safe design/allowlisting becomes essential in those cases. 

## SQL injection examples

Below are concrete technical examples aligned with OWASP’s prevention guidance—showing what unsafe patterns look like and what safe replacements look like. 

### Anatomy of a typical SQLi bug (unsafe)
OWASP shows a typical Java flaw where a request parameter is appended directly into the query string, allowing injected SQL to execute. 

```java
String query = "SELECT account_balance FROM user_data WHERE user_name = "
  + request.getParameter("customerName");

Statement statement = connection.createStatement(...);
ResultSet results = statement.executeQuery(query);
```

### What “in-band / out-of-band / inferential (blind)” means
OWASP categorizes SQLi outcomes as:  
- **In-band**: data extracted via the same channel as the injection (results appear in app response).   
- **Out-of-band**: data retrieved via a different channel (DB triggers a callback, email, DNS/HTTP, etc.).   
- **Inferential / blind**: no direct data returned; attacker infers data from DB/app behavior (timing, errors, boolean response differences).   

## Retrieving hidden data

A common pattern is “authorization-by-query-filter,” where a query includes conditions to hide certain rows (e.g., “only released items”). If the filter predicate is built unsafely, an attacker can alter logic and retrieve rows that should be hidden.  
Defensively, treat all filtering parameters as untrusted data and use parameterized queries so the filter value cannot alter predicate structure. 

## Subverting application logic

SQLi can subvert logic checks that rely on SQL predicates (e.g., login checks, role checks, “only show my records” checks).  
The fix is not “special-casing login” but applying the same primary defense everywhere: parameterized queries/stored procedures without dynamic SQL. 

## Retrieving data from other database tables

If the application returns query results, SQLi may allow reading from tables the feature wasn’t meant to expose. Even if the UI “never shows” those tables, the application’s DB account might still be authorized to read them.  
OWASP’s strongest mitigation for limiting blast radius here is **least privilege**: ensure the application account can only read/write what it truly needs.

## Blind SQL injection vulnerabilities

Blind SQLi exists when the app doesn’t show errors or return query output, but injection still affects execution. OWASP provides two explicit exploitation/validation approaches for blind SQLi:  
- **Time-delay inference** (inject conditional delays and measure response time).   
- **Out-of-band interactions** (trigger a DBMS-driven external request and capture it). 

From a defensive angle, this is important because hiding errors is not a full fix: you still must enforce code/data separation with parameterization and safe query construction. 

## Second-order SQL injection

Second-order SQLi occurs when attacker input is stored first (appears harmless on write), then later used unsafely to build a dynamic query.  
The prevention is the same: never concatenate “trusted” stored data into SQL; always parameterize at the point of query execution. 

## Examining the database

Different DBMS products expose different functions and behaviors (comment syntax, dynamic execution facilities, OOB primitives), which affects how SQLi is exploited and also how you should review code for risky primitives.  
OWASP explicitly flags auditing for dynamic execution functions (e.g., `exec`, `execute`, `sp_execute` in SQL Server stored procedures) as a key code review action. 

## SQL injection in different contexts

SQLi can occur wherever input reaches query construction: URL params, JSON/XML bodies, headers/cookies, and values retrieved from storage (second-order).  
OWASP’s broader Injection Prevention rules emphasize that fixing injection is about safe APIs and correct separation, not about “blocking bad characters.” 

## How to prevent SQL injection

OWASP’s SQL Injection Prevention Cheat Sheet provides **four primary defenses** and recommends additional defenses for defense-in-depth. 

### Primary Defenses

#### Defense Option 1: Prepared Statements (with Parameterized Queries)
OWASP’s top recommendation is prepared statements with variable binding (parameterized queries), because the database distinguishes **code vs data** regardless of attacker input. 
This prevents attackers from changing query intent even if they insert SQL-like characters into an input field. 

Safe Java example (OWASP): 

```java
String custname = request.getParameter("customerName");
// Perform input validation to detect attacks
String query = "SELECT account_balance FROM user_data WHERE user_name = ? ";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, custname);
ResultSet results = pstmt.executeQuery();
```

OWASP also shows safe parameterization patterns in .NET and HQL (Hibernate), emphasizing that abstraction layers can have injection risks too and should still use parameterized APIs. 

#### Defense Option 2: Properly Constructed Stored Procedures
Stored procedures can be as effective as prepared statements **if implemented safely**, meaning they do **not** perform unsafe dynamic SQL generation internally. 
OWASP warns stored procedures can increase risk in some environments if operational constraints push teams to run the app with overly powerful roles (e.g., granting `db_owner` just to make stored procedures work), so you must review privilege models carefully. 
Safe Java stored procedure calling pattern (OWASP): 
```java
String custname = request.getParameter("customerName");
CallableStatement cs = connection.prepareCall("{call sp_getAccountBalance(?)}");
cs.setString(1, custname);
ResultSet results = cs.executeQuery();
```

#### Defense Option 3: Allow-list Input Validation
For SQL query parts that can’t use bind variables (table names, column names, sort direction), OWASP recommends **allowlist validation** or query redesign; ideally, these values come from code, not users. 
If user parameters must influence identifiers, map user choices to a small set of legal/expected identifiers and reject everything else. 

OWASP’s sample safe table-name mapping pattern: 

```java
String tableName;
switch(PARAM) {
  case "Value1": tableName = "fooTable"; break;
  case "Value2": tableName = "barTable"; break;
  default: throw new InputValidationException("unexpected value provided for table name");
}
```

OWASP also shows a safer pattern for simple dynamic sort order: convert to a non-string decision (e.g., boolean) and append only a fixed safe token (`ASC` or `DESC`). 

```java
public String someMethod(boolean sortOrder) {
  String SQLquery = "some SQL ... order by Salary " + (sortOrder ? "ASC" : "DESC");
  ...
}
```

#### Defense Option 4: STRONGLY DISCOURAGED: Escaping All User-Supplied Input
OWASP strongly discourages escaping as a primary strategy: it is DB-specific, fragile, and cannot be guaranteed to prevent all SQLi in all situations. 
Use it only as a last resort for legacy retrofits when safer options are not feasible. 
### Additional Defenses

OWASP recommends adopting additional defenses to reduce blast radius and improve resilience even if a flaw slips through. 

#### Least Privilege (DB and OS)
- Minimize privileges for every DB account; start from required rights and grant only what’s necessary. 
- Do not grant DBA/admin access to application accounts. 
- Use separate DB users for different applications (and even different app components) to enforce granular permissions; OWASP gives the example that login typically needs read-only, while signup needs insert. 
- Consider **views** to restrict access to only necessary fields/rows, and grant access to views instead of base tables where appropriate. 
- Also minimize the **OS account** privileges under which the DBMS runs (avoid running DBMS as root/system). 

#### Allow-list Input Validation (as secondary defense)
Allowlisting can also be used as a detection layer before parameters reach the query, but OWASP cautions: validated data is not automatically safe to concatenate into SQL. 
