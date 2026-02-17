# SQLi-oriented SQL syntax reference (defensive)

This page is a **DBMS syntax** quick reference you’ll commonly need when reviewing, fixing, or validating SQL-injection-prone code paths. [
OWASP’s core message is simple: SQLi happens when apps build dynamic queries with string concatenation and user input; prevent it with parameterized queries/prepared statements, safe stored procedures, allow-lists for identifiers, and avoid “escape everything” approaches. 

## Cross-DBMS syntax essentials

### String concatenation
| DBMS | Syntax |
|---|---|
| Oracle | `'foo'||'bar'` | 
| Microsoft SQL Server | `'foo'+'bar'` | 
| PostgreSQL | `'foo'||'bar'` | 
| MySQL | `'foo' 'bar'` (note the space), `CONCAT('foo','bar')`  [

### Substring (1-based indexing in examples)
All examples return `ba`. 
| DBMS | Syntax |
|---|---|
| Oracle | `SUBSTR('foobar', 4, 2)` | 
| Microsoft SQL Server | `SUBSTRING('foobar', 4, 2)` | 
| PostgreSQL | `SUBSTRING('foobar', 4, 2)` | 
| MySQL | `SUBSTRING('foobar', 4, 2)` | 

### Comments
Comments are legitimate SQL, but they’re also frequently abused during SQLi; treat any app logic that depends on “query tail” structure as fragile. 
| DBMS | Syntax |
|---|---|
| Oracle | `--comment` |
| Microsoft SQL Server | `--comment`, `/*comment*/` |
| PostgreSQL | `--comment`, `/*comment*/` |
| MySQL | `#comment`, `-- comment` (space required), `/*comment*/` |

## Database fingerprinting (safe admin queries)
Knowing the DBMS type/version helps you pick correct syntax and understand platform behavior during secure testing and remediation.

| DBMS | Version query |
|---|---|
| Oracle | `SELECT banner FROM v$version`, `SELECT version FROM v$instance` |
| Microsoft SQL Server | `SELECT @@version` |
| PostgreSQL | `SELECT version()` |
| MySQL | `SELECT @@version` |

## Enumerating schema metadata (tables/columns)
Most non-Oracle DBMSs expose metadata via `information_schema`, while Oracle typically uses `all_*` catalog views.

### List tables
- Oracle:  
  ```sql
  SELECT * FROM all_tables;
  ```


- Microsoft SQL Server / PostgreSQL / MySQL:  
  ```sql
  SELECT * FROM information_schema.tables;
  ```


### List columns in a specific table
- Oracle:  
  ```sql
  SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE';
  ```


- Microsoft SQL Server / PostgreSQL / MySQL:  
  ```sql
  SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE';
  ```

## OWASP prevention patterns (copy/paste-safe)

### 1) Prepared statements / parameterized queries (primary defense)
Prepared statements with variable binding force SQL code to be defined first, then parameters passed separately, so the database distinguishes code from data regardless of input. 
If you do one thing: stop concatenating user input into SQL strings. 

Java (JDBC): 
```java
String custname = request.getParameter("customerName");
String query = "SELECT account_balance FROM user_data WHERE user_name = ? ";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, custname);
ResultSet results = pstmt.executeQuery();
```

C#/.NET (OleDb example): 
```csharp
String query = "SELECT account_balance FROM user_data WHERE user_name = ?";
OleDbCommand command = new OleDbCommand(query, connection);
command.Parameters.Add(new OleDbParameter("customerName", CustomerName.Text));
OleDbDataReader reader = command.ExecuteReader();
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

### 2) Stored procedures (safe when constructed properly)
Stored procedures can prevent SQLi when called with parameters and when they don’t build unsafe dynamic SQL internally. 
Be careful with permission models: giving broad roles just to “make stored procs work” can increase blast radius if the app is compromised. 

Java (CallableStatement): 
```java
String custname = request.getParameter("customerName");
CallableStatement cs = connection.prepareCall("{call sp_getAccountBalance(?)}");
cs.setString(1, custname);
ResultSet results = cs.executeQuery();
```

VB .NET (stored procedure call): 
```vbnet
Dim command As SqlCommand = New SqlCommand("sp_getAccountBalance", connection)
command.CommandType = CommandType.StoredProcedure
command.Parameters.Add(New SqlParameter("@CustomerName", CustomerName.Text))
Dim reader As SqlDataReader = command.ExecuteReader()
```

### 3) Allow-list validation (for identifiers like table/column/order)
Bind variables generally can’t be used for table names, column names, or sort direction, so OWASP recommends redesigning or using strict allow-lists/mappings. 
Treat “user chooses a column/table name” as a design smell; if you can’t remove it, map inputs to known-safe identifiers. 

Java mapping pattern: 
```java
String tableName;
switch (PARAM) {
  case "Value1": tableName = "fooTable"; break;
  case "Value2": tableName = "barTable"; break;
  default: throw new InputValidationException("unexpected value provided for table name");
}
```

Safer dynamic `ORDER BY` direction (convert to boolean/enum before appending): 
```java
public String someMethod(boolean sortOrder) {
  String SQLquery = "some SQL ... order by Salary " + (sortOrder ? "ASC" : "DESC");
  return SQLquery;
}
```

### 4) Escaping input (strongly discouraged)
OWASP explicitly discourages “escape everything” as a primary SQLi defense because it’s database-specific and fragile, and it can’t be relied on to prevent all SQLi cases. 
Prefer parameterized queries, safe stored procedures, or an ORM that builds queries for you.

## Defense-in-depth (OWASP)
Least privilege reduces damage if SQLi exists: grant only the minimum DB rights needed, do not run application DB users with DBA/admin permissions, and consider views to narrow what a given account can read. 
Use different DB users for different app functions (e.g., login read-only vs signup insert-capable) to improve access control granularity. 
If an account only needs part of a table, restrict access via a view instead of granting full table access. 

## Note on “exploit primitives”
PortSwigger’s SQLi cheat sheet includes DBMS-specific examples for conditional errors, stacked queries, time delays, and DNS/OAST behaviors. 
Those techniques are useful for understanding attacker capability and for authorized security validation, but they’re intentionally not reproduced here; focus on eliminating the injection condition with parameterization and least privilege. 
