# SQL injection UNION attacks

When an application is vulnerable to SQL injection and the results of the original query are reflected in the HTTP response, you can often use `UNION` to pull data from other tables in the same database. 
`UNION` lets you run an additional `SELECT` and append its rows to the original result set (for example: `SELECT a, b FROM t1 UNION SELECT c, d FROM t2`). 

## UNION requirements (what must match)
For a `UNION` query to work, both `SELECT` statements must return the same number of columns. 
The data types in each column position must be compatible (or explicitly cast) between the original and injected `SELECT`. 

## Step 1: Find the column count
You typically do this with either `ORDER BY` or `UNION SELECT NULL...` probes. 

### Method A: `ORDER BY` column index
Inject `ORDER BY 1`, then `ORDER BY 2`, etc., until the response changes (error / generic error / empty results) when you exceed the real column count. 
Example payloads (string context):
```text
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
```


### Method B: `UNION SELECT` with `NULL`s
Try `UNION SELECT` with increasing numbers of `NULL` until it succeeds (because `NULL` is usually type-flexible and helps avoid type mismatch while you’re still figuring things out). 
Example payloads:
```text
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```


If the count is wrong, many DBMSs raise a “column count mismatch” style error (sometimes shown verbatim, sometimes hidden behind a generic response). 

## Step 2: Identify which columns can display text
The “interesting” data you want (usernames, emails, API keys) is often string-like, so you need at least one column in the original result set that can hold text. 
After you know the column count, place a string literal in each position one at a time and keep the rest as `NULL`. 

Example (4 columns):
```text
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```


If a column can’t accept text, you’ll typically see a conversion/type error or a generic failure response. 

## Step 3: Retrieve data from other tables
Once you have:
- The number of columns, and 
- At least one text-compatible column to render output, 
you can replace the string probe with real columns from another table. 

Example scenario:
- Original query returns 2 columns.
- Both can hold text.
- There’s a `users` table with `username` and `password`. 

Payload:
```text
' UNION SELECT username, password FROM users--
```


If you don’t know table/column names yet, enumerate schema metadata first (for example using `information_schema` on non-Oracle DBs, or Oracle’s `all_tables` / `all_tab_columns`). 

## Retrieving multiple values in a single column (concatenation)
Sometimes the original query only returns one column, so you need to combine multiple fields into a single string. 
Use a separator you can reliably split on (like `~`), then concatenate values. 

Oracle example:
```text
' UNION SELECT username || '~' || password FROM users--
```


Common concatenation operators by DBMS (useful when you’re building single-column outputs): 
- Oracle / PostgreSQL: `'||'`
- SQL Server: `'+'`
- MySQL: `CONCAT(a,b)` (and in some contexts adjacent string literals) 
## Database-specific syntax notes (common “why isn’t this working?” causes)
Oracle requires `FROM` in every `SELECT`, and a common workaround for constant-only selects is the built-in `dual` table. 
Oracle-style `NULL` column counting:
```text
' UNION SELECT NULL FROM DUAL--
' UNION SELECT NULL,NULL FROM DUAL--
```


SQL comment syntax varies; many payloads use `--` to ignore the remainder of the original query after your injection point. 
On MySQL, `--` typically needs a trailing space, and `#` can also be used as a comment introducer. 

## Type mismatch fixes (when `NULL` isn’t enough)
If you know (or can infer) that a column expects a specific type, you can use explicit casts to satisfy type compatibility rules. 
Example patterns (adjust to the DBMS):
```sql
-- Examples of making types line up (conceptual)
UNION SELECT CAST(NULL AS INT), NULL, NULL
UNION SELECT NULL, CAST('a' AS VARCHAR(100)), NULL
```
