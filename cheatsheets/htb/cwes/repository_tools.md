### Repository Tools

This is a list of repositories that can be used in the HTB CWES to complete the tasks or make the certification. Is not a complete list, but it is a good start.

#### Fuzzing

```
# Web API
git clone https://github.com/PandaSt0rm/webfuzz_api.git

# Obfuscation
git clone https://github.com/Bashfuscator/Bashfuscator.git
  cd Bashfuscator
  ./bashfuscator -c 'cat /etc/passwd'
  ./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1

# Obfuscation
git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
  cd Invoke-DOSfuscation
  Import-Module .\Invoke-DOSfuscation.psd1
  Invoke-DOSfuscation
  SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
  encoding
  1

# SSRF request create
git clone https://github.com/tarunkant/Gopherus.git
cd Gopherus
  chmod +x install.sh
  ./install.sh
  python3 gopherus.py

# SSTI
git clone https://github.com/vladko312/sstimap.git
  cd sstimap
  python3 sstimap.py -u http://example.com/vuln?name=test
  python3 sstimap.py -u http://example.com/vuln -p name

# XXE
git clone https://github.com/enjoiz/XXEinjector.git
  cd XXEinjector
  ruby XXEinjector.rb -u http://example.com/vuln

# LFI
git clone https://github.com/mzfr/liffy.git
  cd liffy
  python3 liffy.py -u http://example.com/vuln?page= -d -i -e 

# GraphQL
git clone https://github.com/dolevf/graphw00f.git
  cd graphw00f
  python3 main.py -d -f -t http://172.17.0.2

git clone https://github.com/APIs-guru/graphql-voyager.git

git clone https://github.com/dolevf/graphql-cop.git
  cd graphql-cop
  python3 graphql-cop.py -t http://example.com -o json

# Jommla
git clone https://github.com/rezasp/joomscan.git
  cd joomscan
  perl joomscan.pl

git clone https://github.com/drego85/JoomlaScan.git
  cd JoomlaScan
  python3 JoomlaScan.py

git clone https://github.com/ajnik/joomla-bruteforce.git
  cd joomla-bruteforce
  python3 joomla-brute.py -u http://example.com -w rockyou.txt -usr admin

# Gitlab
git clone https://github.com/dpgg101/GitLabUserEnum.git
  cd GitLabUserEnum
  python3 gitlab_userenum.py --url URL --wordlist WORDLIST
```

#### Jenkins

A suite resources to make a success pentest agaist Jenkins

```bash
# Github repo
https://github.com/gquere/pwn_jenkins.git

# Jenkins CLI
https://mvnrepository.com/artifact/org.jenkins-ci.main/cli/2.523
```

#### Hydra

A suite resources to make a success pentest using hydra to bruteforce

```
https://bughra.dev/posts/brute-forcing-with-hydra
```

**Made with love by Vishok**