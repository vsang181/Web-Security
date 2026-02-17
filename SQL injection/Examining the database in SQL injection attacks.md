# Examining the database (SQLi context)

When a SQL injection is confirmed, you’ll often need basic database intelligence to choose the right syntax and reliably extract the data you’re authorized to access. 
The two main goals are to identify the DBMS type/version and enumerate tables/columns. 

## Query DB type and version
A common approach is to try DBMS-specific version queries and see which one executes successfully (this also helps fingerprint the backend). 

| Database | Version query |
|---|---|
| Microsoft SQL Server / MySQL | `SELECT @@version` |
| Oracle | `SELECT * FROM v$version` |
| PostgreSQL | `SELECT version()` |

Example result you might see from a SQL Server version query (format varies by deployment): 
```text
Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64)
Mar 18 2018 09:11:49
Copyright (c) Microsoft Corporation
Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64> (Build 14393: ) (Hypervisor)
```

## List tables and columns (non-Oracle)
Most databases (except Oracle) expose metadata via `information_schema`, which is designed to describe the database structure. 
This is typically your fastest path to discovering the relevant tables and their column names/types. 

List tables:
```sql
SELECT * FROM information_schema.tables;
``` 


Example output shape:
```text
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  TABLE_TYPE
=====================================================
MyDatabase     dbo           Products    BASE TABLE
MyDatabase     dbo           Users       BASE TABLE
MyDatabase     dbo           Feedback    BASE TABLE
```


List columns for a specific table:
```sql
SELECT *
FROM information_schema.columns
WHERE table_name = 'Users';
```


Example output shape:
```text
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  COLUMN_NAME  DATA_TYPE
=================================================================
MyDatabase     dbo           Users       UserId       int
MyDatabase     dbo           Users       Username     varchar
MyDatabase     dbo           Users       Password     varchar
```


## Oracle equivalents
Oracle doesn’t use the same `information_schema` views, so you typically enumerate tables and columns via `all_tables` and `all_tab_columns`. 

List tables:
```sql
SELECT * FROM all_tables;
```


List columns for a specific table (Oracle often stores unquoted identifiers in uppercase):
```sql
SELECT *
FROM all_tab_columns
WHERE table_name = 'USERS';
```


## Practical notes
Identifier casing matters: for Oracle, it’s common to query `table_name = 'USERS'` rather than `Users` unless the schema used quoted identifiers. 
When you’re working through metadata, focus on finding “credential-like” or “admin-like” tables/columns (e.g., users, accounts, auth, sessions) and validate assumptions with the column data types you see. 
