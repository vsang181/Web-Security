# SQL injection (SQLi)

> Use the techniques below only on systems you own or have explicit permission to test.

## What SQLi is
SQL injection (SQLi) is a web security vulnerability where attacker-controlled input can change how an application’s SQL query is interpreted by the database. [
It typically happens when applications build **dynamic** SQL with string concatenation using user-supplied input. 
Depending on the query and permissions, SQLi can allow unauthorized reads, data modification/deletion, and sometimes wider impact on backend infrastructure. 

## Impact (why you care)
A successful SQLi can result in unauthorized access to sensitive data (passwords, payment data, personal info). 
SQLi can also cause persistent changes to application content/behavior if attackers can execute `UPDATE`, `INSERT`, or `DELETE` statements via the injection point. 

## Detecting SQLi (systematic tests)
Manual testing involves submitting a small set of inputs to each entry point and comparing responses (errors, content differences, status codes, redirects, and timing). 
Common indicators include SQL errors/anomalies, boolean-driven response changes, time delays, and out-of-band callbacks (OAST). 

- Baseline breakouts (look for errors/anomalies): 
  - `'`  
  - `")` / `')` (context-dependent)
- Boolean probes (look for a consistent true vs false difference): 
  - `OR 1=1`  
  - `OR 1=2`
- Time-based probes (look for consistent response delays): 
  - PostgreSQL: `SELECT pg_sleep(10)` 
  - MySQL: `SELECT SLEEP(10)` 
  - SQL Server: `WAITFOR DELAY '0:0:10'` 
  - Oracle: `dbms_pipe.receive_message(('a'),10)` 
- OAST probes (look for DNS/HTTP interactions from the DB/app tier): 
  - Useful when no errors, no content differences, and no reliable timing differences are observable. 

## Where SQLi happens + common patterns
SQLi is most commonly found in `SELECT ... WHERE ...`, but can also appear in `UPDATE`, `INSERT`, dynamic table/column names, and `ORDER BY`. 
Techniques vary depending on whether results/errors are reflected and on the database platform’s syntax/features. 

- Retrieving “hidden” rows by removing predicates with comments: 
  ```text
  category=Gifts'--
  ```
  ```sql
  SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
  ```

- Login bypass by truncating authentication checks (logic manipulation): 
  ```text
  username=administrator'--   (password left blank)
  ```
  ```sql
  SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
  ```

- UNION-based extraction (when the app reflects query results): 
  ```text
  ' UNION SELECT username, password FROM users--
  ```
  ```sql
  SELECT name, description FROM products WHERE category = '' UNION SELECT username, password FROM users--'
  ```

- Blind SQLi (no reflected results and/or no visible DB errors): 
  - Boolean-based inference: change query logic so the *page behavior* differs based on a true/false condition. 
  - Time-based inference: delay only when a condition is true. 
  - OAST: trigger out-of-band interactions and sometimes exfiltrate data via the out-of-band channel. 

- Second-order (stored) SQLi: input is stored first, then later reused unsafely in a different SQL query. 

- Non-URL inputs: SQLi can show up in JSON/XML bodies, cookies, or headers—any place where controllable input is incorporated into SQL. 
  Some formats can help bypass weak keyword filters via encoding/escaping that is decoded server-side before the SQL parser sees it. 

Example (XML encoding concept; the DB receives the decoded content): 
```xml
<stockCheck>
  <productId>123</productId>
  <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
</stockCheck>
```

## Prevention (OWASP-focused) + examples
OWASP’s primary defenses are: (1) prepared statements / parameterized queries, (2) properly constructed stored procedures, (3) allow-list input validation, and (4) escaping user input (strongly discouraged). 
Prepared statements (variable binding) force the app to define SQL code first and pass parameters separately, so the database distinguishes code from data regardless of attacker input. 
Ensure parameterization is done server-side; some client-side “parameterization” libraries still build SQL via string concatenation before sending it to the server. 

### 1) Prepared statements / parameterized queries (recommended)
Java (JDBC): 
```java
String custname = request.getParameter("customerName");
String query = "SELECT account_balance FROM user_data WHERE user_name = ? ";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, custname);
ResultSet results = pstmt.executeQuery();
```

ASP.NET / SQL Server: 
```csharp
string sql = "SELECT * FROM Customers WHERE CustomerId = @CustomerId";
SqlCommand command = new SqlCommand(sql);
command.Parameters.Add(new SqlParameter("@CustomerId", System.Data.SqlDbType.Int));
command.Parameters["@CustomerId"].Value = 1;
```

PHP (PDO): 
```php
$stmt = $dbh->prepare("INSERT INTO REGISTRY (name, value) VALUES (:name, :value)");
$stmt->bindParam(':name', $name);
$stmt->bindParam(':value', $value);
$stmt->execute();
```

Perl (DBI): 
```perl
my $sql = "INSERT INTO foo (bar, baz) VALUES ( ?, ? )";
my $sth = $dbh->prepare($sql);
$sth->execute($bar, $baz);
```

Rust (SQLx): 
```rust
let username = std::env::args().last().unwrap();

let users: Vec<User> = sqlx::query_as::<_, User>(
    "SELECT * FROM users WHERE name = ?"
)
.bind(&username)
.fetch_all(&pool)
.await
.unwrap();
```

Hibernate (HQL named parameters): 
```java
// Unsafe
Query unsafeHQLQuery =
  session.createQuery("from Inventory where productID='" + userSuppliedParameter + "'");

// Safe
Query safeHQLQuery =
  session.createQuery("from Inventory where productID=:productid");
safeHQLQuery.setParameter("productid", userSuppliedParameter);
```

### 2) Stored procedures (safe when not building dynamic SQL unsafely)
Stored procedures can be effective when implemented safely (no unsafe dynamic SQL generation) and called with bound parameters. 
Dynamic SQL inside stored procedures is a common pitfall; when it’s unavoidable, it should use bind variables. 

Oracle PL/SQL (bind variables with `EXECUTE IMMEDIATE`): 
```sql
PROCEDURE AnotherSafeGetBalanceQuery(UserID varchar, Dept varchar)
AS stmt VARCHAR(400); result NUMBER;
BEGIN
  stmt := 'SELECT balance FROM accounts_table WHERE user_ID = :1 AND department = :2';
  EXECUTE IMMEDIATE stmt INTO result USING UserID, Dept;
  RETURN result;
END;
```

SQL Server (parameterized dynamic SQL with `sp_executesql`): 
```sql
PROCEDURE SafeGetBalanceQuery(@UserID varchar(20), @Dept varchar(10)) AS BEGIN
  DECLARE @sql VARCHAR(200)
  SELECT @sql = 'SELECT balance FROM accounts_table WHERE user_ID = @UID AND department = @DPT'
  EXEC sp_executesql @sql,
    '@UID VARCHAR(20), @DPT VARCHAR(10)',
    @UID=@UserID, @DPT=@Dept
END
```

### 3) Allow-list input validation (for identifiers like table/column/order)
Bind variables can’t be used for table names, column names, or sort direction in many SQL APIs, so OWASP recommends query redesign or strict allow-list mapping. 
If you *must* allow user selection, map user values to known-safe identifiers and reject anything else. 

Java-style table-name mapping (pattern): 
```java
String tableName;
switch (PARAM) {
  case "Value1": tableName = "fooTable"; break;
  case "Value2": tableName = "barTable"; break;
  default:
    throw new InputValidationException("unexpected value provided for table name");
}
```

Safer dynamic `ORDER BY` direction (convert to boolean / enum before appending): 
```java
public String someMethod(boolean sortOrder) {
  String SQLquery = "some SQL ... order by Salary " + (sortOrder ? "ASC" : "DESC");
  return SQLquery;
}
```

### 4) Escaping user input (strongly discouraged)
Escaping is database-specific, frail compared to parameterization, and OWASP does not guarantee it will prevent SQLi in all situations. 
If you need low risk tolerance, build/rewrite using parameterized queries, stored procedures (safely), or an ORM that generates queries for you. 

### Defense-in-depth (recommended extras)
Least privilege: minimize privileges for every DB account, avoid DBA/admin rights for application accounts, and consider separate DB users per app/function (e.g., login page read-only vs signup insert). 
If appropriate, use views to restrict what application accounts can read (e.g., expose only needed fields), reducing blast radius if SQLi occurs. 
Input validation can still be used as a secondary defense to detect unauthorized input, but “validated” data is not automatically safe for string-built SQL. 
