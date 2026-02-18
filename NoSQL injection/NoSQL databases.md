# NoSQL Databases

NoSQL databases represent a category of database management systems designed to store and retrieve data using models other than traditional SQL relational tables with fixed schemas. The term "NoSQL" originally meant "non-SQL" but has evolved to mean "Not Only SQL," acknowledging that these systems complement rather than replace relational databases. NoSQL databases emerged to address the scalability, performance, and flexibility limitations of traditional relational databases when handling massive volumes of unstructured or semi-structured data across distributed systems. Unlike SQL databases that enforce ACID properties (Atomicity, Consistency, Isolation, Durability) and require predefined schemas, NoSQL databases typically prioritize availability and partition tolerance (following the CAP theorem), offer flexible schemas, and use database-specific query languages rather than the universal SQL standard.

The fundamental shift: **NoSQL trades strict consistency and relational structure for scalability, flexibility, and performance** in distributed environments.

## What are NoSQL databases?

### Core characteristics

**Definition:** Database systems that store and retrieve data without using traditional relational table structures.

**Key features:**

**1. Schema flexibility**
```javascript
// SQL - Fixed schema required
CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL
);

// NoSQL (MongoDB) - No predefined schema
db.users.insertOne({
    username: "alice",
    email: "alice@example.com"
});

db.users.insertOne({
    username: "bob",
    email: "bob@example.com",
    age: 30,                    // New field added freely
    preferences: {              // Nested structure
        theme: "dark",
        language: "en"
    }
});
```

**2. Horizontal scalability**
```
SQL (vertical scaling):
├─ Single powerful server
├─ Add more CPU, RAM, storage
└─ Limited by hardware capacity

NoSQL (horizontal scaling):
├─ Multiple commodity servers
├─ Add more servers to cluster
├─ Data distributed across nodes
└─ Linear scalability
```

**3. Eventual consistency (not immediate)**
```
SQL (strong consistency):
Write to database → Immediately visible to all readers

NoSQL (eventual consistency):
Write to database → Replicated asynchronously → Eventually visible
(Trade-off: Better availability and performance)
```

**4. Denormalized data structures**
```javascript
// SQL (normalized) - Multiple tables with joins
Table: users
id | username | email

Table: orders
id | user_id | product | amount

Query: SELECT * FROM users JOIN orders ON users.id = orders.user_id;

// NoSQL (denormalized) - Embedded documents
{
    "_id": 1,
    "username": "alice",
    "email": "alice@example.com",
    "orders": [
        { "product": "Laptop", "amount": 999 },
        { "product": "Mouse", "amount": 25 }
    ]
}
// No joins needed - all data in one document
```

**5. Database-specific query languages**
```javascript
// SQL - Universal language
SELECT * FROM users WHERE age > 25;

// MongoDB - JavaScript-like queries
db.users.find({ age: { $gt: 25 } });

// Redis - Key-value commands
GET user:1001

// Cassandra - CQL (Cassandra Query Language)
SELECT * FROM users WHERE age > 25;

// Neo4j - Cypher query language
MATCH (u:User) WHERE u.age > 25 RETURN u;
```

### NoSQL vs. SQL comparison

| Aspect | SQL (Relational) | NoSQL (Non-relational) |
|--------|------------------|------------------------|
| **Schema** | Fixed, predefined | Flexible, dynamic |
| **Data model** | Tables, rows, columns | Documents, key-value, graphs, columns |
| **Relationships** | Foreign keys, joins | Embedded docs, references |
| **Scalability** | Vertical (scale up) | Horizontal (scale out) |
| **Consistency** | ACID (strong) | BASE (eventual) |
| **Query language** | SQL (universal) | Database-specific |
| **Transactions** | Multi-row ACID | Limited (document-level) |
| **Best for** | Complex queries, relationships | Large-scale, unstructured data |

### When to use NoSQL

**Use NoSQL when:**
- Handling massive volumes of data (terabytes to petabytes)
- Require high write throughput (millions of writes/second)
- Data structure is flexible or frequently changing
- Need horizontal scalability across distributed systems
- Working with unstructured or semi-structured data
- Real-time big data applications (social media, IoT, analytics)
- Geographic distribution of data required

**Use SQL when:**
- Complex relationships between entities
- ACID transactions are critical (banking, financial systems)
- Data structure is stable and well-defined
- Complex queries with multiple joins
- Strong consistency required immediately
- Reporting and business intelligence with complex aggregations

## NoSQL database models

### Model 1: Document stores

**Architecture:** Store data as flexible, semi-structured documents (JSON, BSON, XML).

**Examples:** MongoDB, CouchDB, Couchbase, Amazon DocumentDB

**MongoDB document structure:**
```javascript
{
    "_id": ObjectId("507f1f77bcf86cd799439011"),
    "username": "alice_smith",
    "email": "alice@example.com",
    "profile": {
        "firstName": "Alice",
        "lastName": "Smith",
        "age": 28,
        "location": {
            "city": "London",
            "country": "UK"
        }
    },
    "interests": ["photography", "travel", "coding"],
    "orders": [
        {
            "orderId": "ORD001",
            "product": "Camera",
            "price": 599.99,
            "date": ISODate("2026-02-15T10:30:00Z")
        },
        {
            "orderId": "ORD002",
            "product": "Lens",
            "price": 299.99,
            "date": ISODate("2026-02-16T14:22:00Z")
        }
    ],
    "created": ISODate("2025-01-10T08:00:00Z"),
    "lastLogin": ISODate("2026-02-18T19:30:00Z")
}
```

**Key features:**
- Rich, nested data structures
- Each document can have different fields
- No fixed schema enforcement
- Supports arrays and embedded documents
- Documents grouped in collections

**MongoDB query examples:**

**Insert:**
```javascript
db.users.insertOne({
    username: "bob_jones",
    email: "bob@example.com",
    age: 32
});
```

**Find:**
```javascript
// Find all users over 25
db.users.find({ age: { $gt: 25 } });

// Find with nested field
db.users.find({ "profile.location.city": "London" });

// Find users with specific interest
db.users.find({ interests: "photography" });
```

**Update:**
```javascript
// Update single field
db.users.updateOne(
    { username: "alice_smith" },
    { $set: { "profile.age": 29 } }
);

// Add to array
db.users.updateOne(
    { username: "alice_smith" },
    { $push: { interests: "music" } }
);
```

**Aggregation:**
```javascript
// Complex pipeline queries
db.users.aggregate([
    { $match: { "profile.age": { $gte: 25 } } },
    { $group: { _id: "$profile.location.city", count: { $sum: 1 } } },
    { $sort: { count: -1 } }
]);
```

**Use cases:**
- Content management systems
- User profiles and preferences
- Product catalogs (e-commerce)
- Real-time analytics
- Mobile applications
- Gaming data (player profiles, game state)

### Model 2: Key-value stores

**Architecture:** Simple key-value pairs; value retrieved by unique key.

**Examples:** Redis, Amazon DynamoDB, Riak, Memcached

**Redis data structure:**
```
Key                    Value
-----------------      -------------------------
user:1001              {"name":"Alice","email":"alice@example.com"}
session:abc123         {"userId":1001,"expires":1708282800}
cart:user:1001         ["product:501","product:502","product:503"]
counter:pageviews      1048576
cache:article:42       "<html>Article content...</html>"
```

**Redis examples:**

**Basic operations:**
```bash
# Set key-value
SET user:1001 "Alice"

# Get value
GET user:1001
# Output: "Alice"

# Set with expiration (TTL)
SETEX session:abc123 3600 "user_session_data"

# Check if key exists
EXISTS user:1001
# Output: 1 (true)

# Delete key
DEL user:1001
```

**Data structures:**
```bash
# Strings
SET counter 0
INCR counter
# Output: 1

# Lists (ordered)
LPUSH queue:jobs "job1"
LPUSH queue:jobs "job2"
RPOP queue:jobs
# Output: "job1" (FIFO)

# Sets (unique, unordered)
SADD tags:article:1 "technology"
SADD tags:article:1 "programming"
SADD tags:article:1 "technology"  # Duplicate ignored
SMEMBERS tags:article:1
# Output: ["technology", "programming"]

# Sorted sets (scored)
ZADD leaderboard 100 "player1"
ZADD leaderboard 200 "player2"
ZADD leaderboard 150 "player3"
ZRANGE leaderboard 0 -1 WITHSCORES
# Output: ["player1", "100", "player3", "150", "player2", "200"]

# Hashes (field-value pairs within key)
HSET user:1001 name "Alice"
HSET user:1001 email "alice@example.com"
HSET user:1001 age "28"
HGETALL user:1001
# Output: {"name":"Alice","email":"alice@example.com","age":"28"}
```

**Advanced features:**
```bash
# Pub/Sub messaging
SUBSCRIBE notifications
PUBLISH notifications "New message"

# Transactions
MULTI
SET key1 "value1"
SET key2 "value2"
EXEC

# Lua scripting
EVAL "return redis.call('GET', KEYS[1])" 1 mykey
```

**Use cases:**
- Session storage (web applications)
- Caching layer (frequently accessed data)
- Real-time leaderboards (gaming)
- Rate limiting (API throttling)
- Message queues
- Shopping cart data
- Temporary data with TTL

### Model 3: Wide-column stores

**Architecture:** Store data in column families rather than rows; columns grouped by access patterns.

**Examples:** Apache Cassandra, Apache HBase, Google Bigtable, ScyllaDB

**Cassandra data model:**
```
Table: users_by_location

Row Key: UK:London
├─ Column: user:alice_smith
│  └─ Value: {"email":"alice@example.com","age":28}
├─ Column: user:bob_jones
│  └─ Value: {"email":"bob@example.com","age":32}
└─ Column: user:carol_white
   └─ Value: {"email":"carol@example.com","age":25}

Row Key: US:NewYork
├─ Column: user:david_brown
│  └─ Value: {"email":"david@example.com","age":35}
└─ Column: user:eve_wilson
   └─ Value: {"email":"eve@example.com","age":29}
```

**Cassandra CQL examples:**

**Create table:**
```sql
CREATE TABLE users (
    user_id UUID PRIMARY KEY,
    username TEXT,
    email TEXT,
    age INT,
    location TEXT,
    created_at TIMESTAMP
);

-- Composite partition key
CREATE TABLE users_by_location (
    country TEXT,
    city TEXT,
    user_id UUID,
    username TEXT,
    email TEXT,
    PRIMARY KEY ((country, city), user_id)
);
```

**Insert data:**
```sql
INSERT INTO users_by_location (country, city, user_id, username, email)
VALUES ('UK', 'London', uuid(), 'alice_smith', 'alice@example.com');
```

**Query data:**
```sql
-- Query by partition key (efficient)
SELECT * FROM users_by_location 
WHERE country = 'UK' AND city = 'London';

-- Query specific columns
SELECT username, email FROM users_by_location
WHERE country = 'UK' AND city = 'London';
```

**Key characteristics:**
- Optimized for write-heavy workloads
- Partition keys determine data distribution
- Clustering keys determine sort order within partition
- Denormalized data model (query-driven design)
- High availability with no single point of failure

**Use cases:**
- Time-series data (IoT sensor readings, logs)
- Event tracking (clickstream data, user activity)
- Messaging systems (chat histories)
- Product recommendations (user behavior data)
- Financial transactions (high write throughput)
- Network monitoring data

### Model 4: Graph databases

**Architecture:** Store data as nodes (entities) and edges (relationships).

**Examples:** Neo4j, Amazon Neptune, ArangoDB, JanusGraph

**Graph structure:**
```
Nodes (entities):
(Person:Alice {name:"Alice Smith", age:28})
(Person:Bob {name:"Bob Jones", age:32})
(Company:TechCorp {name:"TechCorp", industry:"Technology"})
(Product:Laptop {name:"UltraBook Pro", price:999})

Edges (relationships):
(Alice)-[:WORKS_AT {since:2020, role:"Engineer"}]->(TechCorp)
(Bob)-[:WORKS_AT {since:2018, role:"Manager"}]->(TechCorp)
(Alice)-[:FRIENDS_WITH {since:2015}]->(Bob)
(Bob)-[:PURCHASED {date:"2026-02-15", quantity:1}]->(Laptop)
(Alice)-[:LIKES]->(Laptop)
```

**Neo4j Cypher examples:**

**Create nodes:**
```cypher
// Create person node
CREATE (alice:Person {name: "Alice Smith", age: 28, city: "London"})

// Create company node
CREATE (techcorp:Company {name: "TechCorp", industry: "Technology"})

// Create product node
CREATE (laptop:Product {name: "UltraBook Pro", price: 999})
```

**Create relationships:**
```cypher
// Create employment relationship
MATCH (alice:Person {name: "Alice Smith"}),
      (techcorp:Company {name: "TechCorp"})
CREATE (alice)-[:WORKS_AT {since: 2020, role: "Engineer"}]->(techcorp)

// Create friendship
MATCH (alice:Person {name: "Alice Smith"}),
      (bob:Person {name: "Bob Jones"})
CREATE (alice)-[:FRIENDS_WITH {since: 2015}]->(bob)
```

**Query relationships:**
```cypher
// Find Alice's friends
MATCH (alice:Person {name: "Alice Smith"})-[:FRIENDS_WITH]->(friend)
RETURN friend.name

// Find Alice's colleagues
MATCH (alice:Person {name: "Alice Smith"})-[:WORKS_AT]->(company)
      <-[:WORKS_AT]-(colleague)
RETURN colleague.name

// Find friends of friends
MATCH (alice:Person {name: "Alice Smith"})-[:FRIENDS_WITH]->()
      -[:FRIENDS_WITH]->(foaf)
WHERE foaf.name <> "Alice Smith"
RETURN DISTINCT foaf.name

// Product recommendations based on friend purchases
MATCH (alice:Person {name: "Alice Smith"})-[:FRIENDS_WITH]->(friend)
      -[:PURCHASED]->(product)
WHERE NOT (alice)-[:PURCHASED]->(product)
RETURN product.name, COUNT(*) AS friend_purchases
ORDER BY friend_purchases DESC
LIMIT 5
```

**Complex traversals:**
```cypher
// Shortest path between two people
MATCH path = shortestPath(
    (alice:Person {name: "Alice Smith"})-[*]-(stranger:Person {name: "Eve Wilson"})
)
RETURN path

// Find influencers (highly connected people)
MATCH (person:Person)-[:FRIENDS_WITH]->(friend)
WITH person, COUNT(friend) AS friendCount
WHERE friendCount > 10
RETURN person.name, friendCount
ORDER BY friendCount DESC
```

**Use cases:**
- Social networks (friend connections, recommendations)
- Fraud detection (transaction patterns, network analysis)
- Knowledge graphs (Wikipedia, semantic web)
- Recommendation engines (products, content, people)
- Network and IT operations (topology, dependencies)
- Identity and access management (permissions, roles)
- Supply chain management (logistics, dependencies)

## Query languages comparison

### SQL (Relational databases)
```sql
-- Universal syntax across databases
SELECT u.username, o.product, o.amount
FROM users u
JOIN orders o ON u.id = o.user_id
WHERE u.age > 25 AND o.amount > 100
ORDER BY o.amount DESC
LIMIT 10;
```

### MongoDB Query Language (MQL)
```javascript
// JavaScript-like syntax
db.users.aggregate([
    {
        $match: { age: { $gt: 25 } }
    },
    {
        $lookup: {
            from: "orders",
            localField: "_id",
            foreignField: "userId",
            as: "orders"
        }
    },
    {
        $unwind: "$orders"
    },
    {
        $match: { "orders.amount": { $gt: 100 } }
    },
    {
        $project: {
            username: 1,
            product: "$orders.product",
            amount: "$orders.amount"
        }
    },
    {
        $sort: { amount: -1 }
    },
    {
        $limit: 10
    }
]);
```

### Redis Commands
```bash
# Imperative commands
HGETALL user:1001
ZADD leaderboard 100 player1
GET session:abc123
```

### Cassandra CQL
```sql
-- SQL-like but with limitations
SELECT username, product, amount
FROM orders_by_user
WHERE user_id = 123 AND amount > 100
ORDER BY amount DESC
LIMIT 10;
```

### Neo4j Cypher
```cypher
// Pattern-matching syntax
MATCH (u:User)-[:PLACED]->(o:Order)
WHERE u.age > 25 AND o.amount > 100
RETURN u.username, o.product, o.amount
ORDER BY o.amount DESC
LIMIT 10
```

## Consistency models

### ACID (SQL databases)
```
Atomicity: All-or-nothing transactions
Consistency: Database remains in valid state
Isolation: Concurrent transactions don't interfere
Durability: Committed data persists
```

### BASE (NoSQL databases)
```
Basically Available: System guarantees availability
Soft state: State may change without input (eventual consistency)
Eventual consistency: System will become consistent over time
```

### CAP Theorem trade-offs
```
CAP Theorem: Can only achieve 2 of 3:
- Consistency: All nodes see same data
- Availability: System responds to requests
- Partition tolerance: System works despite network splits

NoSQL databases choose:
- MongoDB: CP (Consistency + Partition tolerance)
- Cassandra: AP (Availability + Partition tolerance)
- Redis: CP (Consistency + Partition tolerance)
```

## Real-world architecture example

### E-commerce application using multiple NoSQL databases

**MongoDB (Document store) - Product catalog:**
```javascript
{
    "productId": "PROD001",
    "name": "UltraBook Pro",
    "description": "High-performance laptop...",
    "price": 999,
    "specifications": {
        "cpu": "Intel i7",
        "ram": "16GB",
        "storage": "512GB SSD"
    },
    "images": [
        "https://cdn.example.com/prod001-1.jpg",
        "https://cdn.example.com/prod001-2.jpg"
    ],
    "reviews": [
        {
            "user": "alice",
            "rating": 5,
            "comment": "Excellent laptop!"
        }
    ]
}
```

**Redis (Key-value store) - Session and caching:**
```bash
# User session
SET session:abc123 '{"userId":1001,"cart":["PROD001","PROD002"]}'
EXPIRE session:abc123 3600

# Product cache
SET cache:product:PROD001 '{"name":"UltraBook Pro","price":999}'
EXPIRE cache:product:PROD001 300

# Shopping cart
SADD cart:user:1001 "PROD001"
SADD cart:user:1001 "PROD002"
```

**Cassandra (Wide-column store) - Order history:**
```sql
CREATE TABLE orders_by_user (
    user_id UUID,
    order_date TIMESTAMP,
    order_id UUID,
    product_id TEXT,
    amount DECIMAL,
    PRIMARY KEY (user_id, order_date, order_id)
) WITH CLUSTERING ORDER BY (order_date DESC);
```

**Neo4j (Graph database) - Recommendations:**
```cypher
// Find products purchased by users with similar interests
MATCH (user:User {id: 1001})-[:INTERESTED_IN]->(interest)
      <-[:INTERESTED_IN]-(similar:User)
      -[:PURCHASED]->(product)
WHERE NOT (user)-[:PURCHASED]->(product)
RETURN product, COUNT(*) AS score
ORDER BY score DESC
LIMIT 10
```

NoSQL databases represent a fundamental architectural shift from traditional relational databases, prioritizing scalability, flexibility, and performance for distributed systems handling massive volumes of unstructured data. The four primary NoSQL models—document stores (MongoDB), key-value stores (Redis), wide-column stores (Cassandra), and graph databases (Neo4j)—each optimize for different use cases and access patterns rather than attempting to be general-purpose solutions. Unlike SQL's universal query language, NoSQL databases employ database-specific query interfaces ranging from JavaScript-like syntax (MongoDB) to pattern-matching languages (Neo4j Cypher), requiring developers to understand each system's unique characteristics and trade-offs in consistency, availability, and partition tolerance defined by the CAP theorem.
