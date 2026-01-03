### Wireshark Filters Cheat Sheet

**Wireshark** is an essential tool for network analysis and security auditing. This cheatsheet provides a comprehensive guide to filtering network traffic for security analysis, incident response, and network troubleshooting.

-----

### Understanding Wireshark Filters

* **Display vs. Capture Filters**
  * **Display Filters:** Applied post-capture to filter the view (e.g., `http` shows only HTTP traffic)
  * **Capture Filters:** Applied during packet capture to reduce noise

* **Filter Syntax**
  * **Logical operators:** `and`, `or`, `not`, `&&`, `||`, `!`
  * **Comparison:** `==` (equal), `!=` (not equal), `>` (greater than), `<` (less than)
  * **Contains:** `contains`, `matches` (regex)

-----

### Basic Filter Examples

#### Filter HTTP traffic to/from specific IP

```bash
http and (ip.src == 192.168.1.100 or ip.dst == 192.168.1.100)
```

* **Why it's used:** To isolate web traffic for a specific host during security analysis.
* **How it works:** Combines HTTP protocol filter with source/destination IP conditions.

#### Find failed login attempts

```bash
http.response.code == 401 or http.response.code == 403
```

* **Why it's used:** To identify authentication failures and potential brute force attacks.
* **How it works:** Filters HTTP responses for unauthorized (401) and forbidden (403) status codes.

#### Detect potential port scanning

```bash
tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.dstport != 80
```

* **Why it's used:** To identify SYN scans that exclude common web traffic.
* **How it works:** Looks for TCP SYN packets without ACK flags targeting non-standard ports.

-----

### Data and Payload Analysis

#### Packet Content Inspection

| Filter | Description | Example | Why Use This |
| :--- | :--- | :--- | :--- |
| `data` | Searches raw packet data | `data contains "password"` | Find sensitive data in plaintext traffic |
| `data.data` | Raw payload data | `data.data contains "secret"` | Locate specific binary patterns |
| `data.text` | Text representation of data | `data.text contains "login"` | Search for readable text in binary protocols |
| `file_data` | Extracted file data | `file_data contains "confidential"` | Analyze files transferred over network |
| `tcp.payload` | Raw TCP payload | `tcp.payload contains "GET"` | Inspect raw HTTP requests |
| `udp.payload` | Raw UDP payload | `udp.payload contains "query"` | Analyze DNS or other UDP-based protocols |
| `icmp.data` | ICMP packet data | `icmp.data contains "backdoor"` | Detect ICMP tunneling or exfiltration |

#### Practical Examples

```bash
# Find potential credentials in plaintext
frame contains "password=" or frame contains "passwd=" or frame contains "pwd="

# Detect potential data exfiltration
http.request.method == "POST" and http.file_data matches "[0-9a-f]{32}"

# Find large file transfers
frame.len > 1000 and tcp.len > 1000
```

* **Why it's used:** To identify data leakage, credential exposure, and suspicious file transfers.
* **How it works:** Uses string matching and regular expressions to detect patterns in network payloads.

-----

### DNS Traffic Analysis

#### DNS Query/Response Inspection

| Filter | Description | Example | Why Use This |
| :--- | :--- | :--- | :--- |
| `dns.qry.name` | DNS query names | `dns.qry.name contains "malware"` | Detect malicious domains |
| `dns.resp.name` | DNS response names | `dns.resp.name contains "google"` | Track domain resolutions |
| `dns.txt` | DNS TXT records | `dns.txt contains "v=spf1"` | Analyze email security settings |
| `dns.flags.response` | Filter queries (0) or responses (1) | `dns.flags.response == 0` | Separate queries from responses |
| `dns.resp.type` | DNS record type | `dns.resp.type == 1` (A record) | Filter by record type |

#### Practical Examples

```bash
# Find DNS queries to known malicious domains
dns.qry.name matches "\.(xyz|top|gq)$" and dns.flags.response == 0

# Detect DNS tunneling attempts (long subdomains)
dns.qry.name matches "^[a-z0-9]{30,}"

# Find DNS exfiltration attempts
dns.qry.name contains "base64" or dns.qry.name matches "[0-9a-f]{32}"
```

* **Why it's used:** DNS is often overlooked but can be used for command and control, data exfiltration, and network reconnaissance.
* **How it works:** Filters DNS traffic based on domain patterns, query characteristics, and response types.

-----

### HTTP Traffic Analysis

#### HTTP Request/Response Inspection

| Filter | Description | Example | Why Use This |
| :--- | :--- | :--- | :--- |
| `http.request.uri` | Requested URI/URL | `http.request.uri contains ".php"` | Find specific endpoints |
| `http.request.body` | Request body content | `http.request.body contains "password"` | Find form submissions |
| `http.response.body` | Response content | `http.response.body contains "error"` | Locate error messages |
| `http.server` | Server header | `http.server contains "nginx"` | Identify web server types |
| `http.location` | Redirect URLs | `http.location contains "login"` | Track redirects |
| `http.referer` | Referring page | `http.referer contains "google"` | Track traffic sources |
| `http.authorization` | Auth headers | `http.authorization contains "Basic"` | Find authentication attempts |
| `http.cookie` | Cookie data | `http.cookie contains "session"` | Track session handling |
| `http.user_agent` | Client browser/agent | `http.user_agent contains "sqlmap"` | Detect scanning tools |

#### Practical Examples

```bash
# Find file uploads
http.request.method == "POST" and http.content_type contains "multipart/form-data"

# Detect SQL injection attempts
http.request.uri matches "'.*--|'.*'\s*OR\s*'|'.*;--"

# Find API keys in responses
http.response.body matches "[a-zA-Z0-9]{32}" or http.response.body matches "[a-zA-Z0-9]{40}"

# Detect web shells
http.request.uri matches "\.(php|asp|aspx|jsp)" and http.request.uri matches "(cmd|shell|backdoor)"
```

* **Why it's used:** To monitor web application traffic for security incidents, attacks, and data exposure.
* **How it works:** Filters HTTP traffic based on request methods, content patterns, headers, and response characteristics.

-----

### Protocol-Specific Analysis

#### FTP Traffic

| Filter | Description | Example | Why Use This |
| :--- | :--- | :--- | :--- |
| `ftp.request.command` | FTP commands | `ftp.request.command == "USER"` | Monitor authentication |
| `ftp.response.code` | FTP response codes | `ftp.response.code == 530` | Find failed logins |
| `ftp-data` | FTP data channel | `ftp-data` | Inspect file transfers |

#### SMTP Traffic

| Filter | Description | Example | Why Use This |
| :--- | :--- | :--- | :--- |
| `smtp.req.command` | SMTP commands | `smtp.req.command == "MAIL"` | Track email flow |
| `smtp.response.code` | SMTP responses | `smtp.response.code == 550` | Find failed deliveries |
| `smtp.data` | Email content | `smtp.data contains "confidential"` | Inspect email bodies |

#### SSH Traffic

| Filter | Description | Example | Why Use This |
| :--- | :--- | :--- | :--- |
| `ssh.protocol` | SSH version | `ssh.protocol contains "SSH-2.0"` | Detect SSH version |
| `ssh.message_code` | SSH message type | `ssh.message_code == 21` (User auth success) | Track authentication |
| `ssh.encrypted_packet` | Encrypted SSH data | `ssh.encrypted_packet` | Identify encrypted sessions |

#### Practical Examples

```bash
# Detect FTP brute force attempts
ftp.response.code == 530 and frame.count > 5

# Find emails with attachments
smtp.data.fragment contains "Content-Type: application/"

# Detect SSH version 1 (insecure)
ssh.protocol contains "SSH-1.99" or ssh.protocol contains "SSH-1.5"

# Find large file transfers over FTP
ftp-data and frame.len > 10000
```

* **Why it's used:** To analyze specific application protocols for security incidents and policy violations.
* **How it works:** Uses protocol-specific fields to filter and analyze different types of network traffic.

-----

### Usage Tips

* **Combine filters:** `http and tcp.port == 80 and ip.src == 192.168.1.1`
* **Export data:** `tshark -r capture.pcap -Y "http" -T fields -e http.request.uri > uris.txt`
* **For CTFs:** look for anomalies like unusual ports, hidden data, or auth headers.
* **Practice:** with sample PCAPs from Wireshark's website.

-----

**Made with love by VIsh0k**