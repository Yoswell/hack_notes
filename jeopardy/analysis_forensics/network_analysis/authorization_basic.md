### HTTP Basic Authorization

HTTP Basic Authorization is a simple authentication scheme used in HTTP communications where the client sends a username and password to access protected resources. Credentials are encoded in Base64 and transmitted in the `Authorization` header. While straightforward, it's inherently insecure over unencrypted connections due to the lack of encryption.

In CTF challenges, Basic Auth is often encountered in network forensics, where credentials can be extracted from PCAP files or used to brute-force weak passwords.

#### How It Works

  1. **Client Request**: The client sends an HTTP request with an `Authorization` header.
  2. **Header Format**: `Authorization: Basic <base64_encoded_credentials>`
    * `<base64_encoded_credentials>` is the Base64 encoding of `username:password`.
  3. **Server Verification**: The server decodes the credentials and verifies them against its user database.
  4. **Response**: If valid, access is granted; otherwise, a 401 Unauthorized response is sent.

#### Decoding Credentials

To decode Base64 credentials:

  * Use online tools like [Base64 Decode](https://www.base64decode.org) or command-line: `echo "dG9tY2F0OnMzY3IzdA==" | base64 -d`
  * Example: `dG9tY2F0OnMzY3IzdA==` decodes to `tomcat:s3cr3t`

#### Example HTTP Request

  ```
  GET /manager/html HTTP/1.1
  Host: 10.0.0.112:8080
  User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
  Accept-Language: en-US,en;q=0.5
  Accept-Encoding: gzip, deflate
  Connection: keep-alive
  Upgrade-Insecure-Requests: 1
  Authorization: Basic dG9tY2F0OnMzY3IzdA==
  ```

  Decoded Credentials: `tomcat:s3cr3t`

#### Security Risks

  * **No Encryption**: Credentials are sent in plain Base64, easily decoded. Always use HTTPS.
  * **Replay Attacks**: Captured headers can be reused.
  * **Brute-Force**: Weak passwords are vulnerable to dictionary attacks.
  * **Logging**: Servers may log credentials in access logs.

#### Mitigation

  * Use HTTPS to encrypt the connection.
  * Implement stronger auth like OAuth, JWT, or Digest Auth.
  * Enforce strong passwords and rate limiting.
  * Avoid Basic Auth for sensitive applications; prefer token-based systems.

#### Wireshark Extraction

  * **To extract Basic Auth from PCAP**

  ```bash
  tshark -r capture.pcap -Y "http.authorization contains Basic" -T fields -e http.authorization
  ```
   
  Decode the Base64 part for credentials.

-----

**Made with love by VIsh0k**
