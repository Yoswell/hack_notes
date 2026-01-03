### NETNTLMv2 Hashes

**NTLM (NT LAN Manager)** is a suite of Microsoft security protocols for authentication. **NTLMv2** is an improved version that enhances security over NTLMv1 by using stronger hashing and incorporating timestamps and client challenges.

* **Protocol Family:** Microsoft authentication protocol suite
* **Version:** NTLMv2 - enhanced security version
* **Security Improvements:** Stronger hashing, timestamp integration, client challenges
* **Attack Vector:** Captured NTLMv2 hashes can be used for offline brute-force or dictionary attacks
* **CTF Relevance:** Often captured from network traffic (SMB, HTTP NTLM auth) and cracked to gain credentials

-----

### How NTLMv2 Works

Understanding the authentication flow and hash generation process.

#### Client Negotiation

```
Client sends negotiate message indicating NTLMv2 support
```

* **Why it's important:** Initiates the authentication handshake and declares protocol capabilities.

#### Server Challenge

```
Server responds with a random 8-byte server challenge
```

* **Why it's important:** Provides unique randomness to prevent replay attacks.

#### Client Response Computation

```
Client uses username, domain, password hash, server challenge, and client challenge to generate NTProofStr
```

* **Why it's important:** Creates the cryptographic proof of password knowledge.

#### Authentication Verification

```
Server verifies the response using stored credentials
```

* **Why it's important:** Completes the authentication process and grants or denies access.

#### Hash Structure

```
User::Domain:ServerChallenge:NTProofStr:ClientChallenge
```
* **Why it's important:** Standard format for hash capture and cracking tools.

-----

### Extraction Commands

Using TShark (command-line Wireshark) to extract NTLMv2 components from PCAP files.

#### Extract Full Response

```bash
tshark -r whispered.pcap -T fields -Y 'tls and ntlmssp' -e ntlmssp.ntlmv2_response | xxd -p -r
```

* **When to use:** To get the complete NTLMv2 response for analysis.
* **Output:** Raw binary response that can be converted to hex.

#### Extract NTProofStr (Hash)

```bash
tshark -r whispered.pcap -T fields -Y 'tls and ntlmssp' -e ntlmssp.ntlmv2_response.ntproofstr | xxd -p -r
```

* **When to use:** To isolate the actual hash value for cracking.
* **Importance:** This is the primary target for password recovery attacks.

#### Extract Domain Name

```bash
tshark -r whispered.pcap -T fields -Y 'tls and ntlmssp' -e ntlmssp.auth.domain | xxd -p -r
```

* **When to use:** To identify the authentication domain.
* **Format:** Usually Windows domain or computer name.

#### Extract Username

```bash
tshark -r whispered.pcap -T fields -Y 'tls and ntlmssp' -e ntlmssp.auth.username | xxd -p -r
```

* **When to use:** To identify the target user account.
* **Usage:** Combined with domain for user identification.

#### Extract Server Challenge

```bash
tshark -r whispered.pcap -T fields -Y 'tls and ntlmssp' -e ntlmssp.challenge.target_name | xxd -p -r
```

* **When to use:** To get the random challenge used in hash generation.
* **Length:** 8-byte (16 character hex) value.

-----

### Cracking the Hash

Tools and techniques for cracking extracted NTLMv2 hashes.

#### Basic Hashcat Command

```bash
hashcat -m 5600 -a 0 hash.txt wordlist.txt
```

* **Mode:** `-m 5600` specifies NETNTLMv2 hash type.
* **Attack Type:** `-a 0` for straight dictionary attack.
* **Files:** `hash.txt` contains formatted hash, `wordlist.txt` contains password candidates.

#### Advanced Hashcat Options

```bash
hashcat -m 5600 -a 3 hash.txt ?a?a?a?a?a?a?a?a
```

* **When to use:** For brute-force attacks with mask patterns.
* **Pattern:** `?a` tries all printable ASCII characters.

#### Basic John Command

```bash
john hash.txt --wordlist=wordlist.txt --format=netntlmv2
```

* **Format:** `--format=netntlmv2` specifies hash type.
* **Wordlist:** `--wordlist=` specifies password dictionary.

#### John with Rules

```bash
john hash.txt --wordlist=wordlist.txt --format=netntlmv2 --rules
```

* **When to use:** To apply mangling rules to wordlist entries.
* **Benefit:** Increases cracking success rate with variations.

-----

### Example Capture and Extraction

Real-world example of NTLMv2 hash capture and formatting.

#### NTLMv2 Response

```
NTLM Response […]: dfd11fbf2eb8b0bf3ce284156ecb0184010100000000000060f31ac...
```

* **What it is:** Complete authentication response including client data.
* **Length:** Variable based on authentication context.

#### NTProofStr (Core Hash)

```
NTProofStr: dfd11fbf2eb8b0bf3ce284156ecb0184
```

* **What it is:** 16-byte (32 character) hash value derived from password.
* **Usage:** Primary target for password cracking.

#### Domain Information

```
Domain name: DESKTOP-6NMJS1R
```

* **What it is:** Windows computer name used as domain in workgroup.
* **Format:** Typically computer name for standalone systems.

#### Username

```
Username: stoneheart_keeper52
```

* **What it is:** Target user account attempting authentication.
* **Format:** Windows username, may include special characters.

#### Server Challenge

```
NTLM Server Challenge: 08d934957c1edac2
```

* **What it is:** 8-byte random value generated by server.
* **Purpose:** Prevents replay attacks and ensures freshness.

#### Formatted Hash for Cracking

#### Complete Hash Format

```
stoneheart_keeper52::DESKTOP-6NMJS1R:08d934957c1edac2:dfd11fbf2eb8b0bf3ce284156ecb0184:010100000000000060f31ac5f541dc01824bc272011e5aa30000000002001e004400450053004b0054004f0050002d0036004e004d004a0053003100520001001e004400450053004b0054004f0050002d0036004e004d004a0053003100520004001e004400450053004b0054004f0050002d0036004e004d004a0053003100520003001e004400450053004b0054004f0050002d0036004e004d004a005300310052000700080099f625c5f541dc0109004e007400650072006d007300720076002f004400450053004b0054004f0050002d0036004e004d004a0053003100520040004400450053004b0054004f0050002d0036004e004d004a005300310052000000000000000000
```

* **Structure:** `User::Domain:ServerChallenge:NTProofStr:ClientChallenge`
* **Tool Compatibility:** Format accepted by Hashcat and John the Ripper.

-----

### Security Notes

Important security considerations regarding NTLMv2.

#### Protocol Vulnerabilities

```
NTLMv2 is more secure than v1 but still vulnerable to pass-the-hash attacks
```

* **Why it matters:** Attackers can reuse captured hashes without cracking passwords.

#### Modern Alternatives

```
Use Kerberos instead for better security in Windows environments
```

* **Why it's better:** Kerberos provides mutual authentication and ticket-based security.

#### CTF Capture Techniques

```
Always capture traffic over insecure protocols to extract hashes
```

* **Where to look:** SMB, HTTP NTLM authentication, LDAP, and other Microsoft protocols.

#### Defensive Measures

```
Disable NTLM when possible, use NTLMv2 exclusively, implement SMB signing
```

* **Best practices:** Minimize NTLM usage and enforce strongest available security settings.

-----

**Made with love by VIsh0k**