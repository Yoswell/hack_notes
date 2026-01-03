### CouchDB

**CouchDB** is an open-source NoSQL document database that stores data in JSON format and uses HTTP for communication. It differs from relational databases in its flexible schema, which allows for scalable and distributed data management, especially in web and mobile applications using a RESTful API.

* **Architecture:** Document-oriented database storing data as JSON documents
* **Communication Protocol:** Uses HTTP for all operations (RESTful API)
* **Design Philosophy:** Ease of use, scalability, and distributed data management
* **Common Use Cases:** Web applications, mobile apps, CTF challenges involving database enumeration, data extraction, or exploitation of misconfigured CouchDB instances

-----

### Key Features

Understanding CouchDB's distinctive characteristics and capabilities.

#### Document-Oriented Storage

```
Stores data as JSON documents rather than tables
```

* **Why it's important:** Flexible schema allows for evolving data structures without migrations.

#### RESTful API Architecture

```
All operations are performed via HTTP requests (GET, POST, PUT, DELETE)
```

* **Why it's important:** Simplifies integration and makes the database accessible from any HTTP client.

#### Replication Capabilities

```
Supports master-master replication for distributed setups
```

* **Why it's important:** Enables offline-first applications and distributed data management.

#### Query System

```
Uses MapReduce for querying data through views
```

* **Why it's important:** Provides powerful, customizable query capabilities for JSON documents.

#### Security Features

```
Supports authentication, authorization, and SSL/TLS
```

* **Why it's important:** Essential for protecting sensitive data in production environments.

-----

### Common Endpoints and Operations

Essential CouchDB API endpoints for database management and document operations.

#### List All Databases

```bash
GET /_all_dbs
```

**When to use:** To enumerate available databases on a CouchDB instance.

#### Create New Database

```bash
PUT /<database_name>
```

**When to use:** To create a new database with the specified name.

#### Retrieve All Documents

```bash
GET /<database_name>/_all_docs
```

**When to use:** To list all documents in a specific database.

#### Create New Document

```bash
POST /<database_name>
```

**When to use:** To insert a new document into a database (auto-generated ID).

#### Retrieve Specific Document

```bash
GET /<database_name>/<doc_id>
```

**When to use:** To fetch a document by its unique identifier.

#### Update Existing Document

```bash
PUT /<database_name>/<doc_id>
```

**When to use:** To modify an existing document (requires current revision).

#### Delete Document

```bash
DELETE /<database_name>/<doc_id>
```

**When to use:** To remove a document from the database (requires revision).

-----

### Example Queries

Practical examples of CouchDB operations using cURL.

#### List Databases

```bash
curl -X GET http://localhost:5984/_all_dbs
```

* **When to use:** Initial reconnaissance to discover available databases.
* **Response:** Returns a JSON array of database names.

#### Create Database

```bash
curl -X PUT http://localhost:5984/mydb
```

* **When to use:** Setting up a new database for testing or data storage.
* **Response:** Confirmation JSON with success status.

#### Insert Document

```bash
curl -X POST http://localhost:5984/mydb \
  -H "Content-Type: application/json" \
  -d '{"name": "example", "value": "test"}'
```

* **When to use:** Adding data to a database.
* **Response:** Document creation confirmation with generated ID and revision.

#### Retrieve All Documents

```bash
curl -X GET http://localhost:5984/mydb/_all_docs
```

* **When to use:** Enumerating all documents in a database.
* **Response:** JSON containing document IDs and basic metadata.

#### Get Specific Document

```bash
curl -X GET http://localhost:5984/mydb/document_id
```

* **When to use:** Accessing a particular document's content.
* **Response:** Complete JSON document with all fields.

-----

### Security Notes

Important security considerations for CouchDB deployment and assessment.

#### Default Configuration Risks

```
Default installations may have admin access without authentication
```

* **Why it's critical:** Unauthenticated admin access can lead to complete system compromise.

#### Exposure Vulnerabilities

```
Vulnerable to unauthorized access if exposed publicly without proper configuration
```

* **Why it's critical:** Publicly accessible CouchDB instances are common targets for attackers.

#### CTF Assessment Tools

```
Use tools like couchdb-python or direct HTTP requests for enumeration in CTFs
```

* **Why it's useful:** These tools help identify misconfigurations and exposed data.

-----

**Made with love by VIsh0k**