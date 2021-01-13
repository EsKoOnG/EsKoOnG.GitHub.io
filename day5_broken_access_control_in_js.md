# [Code4Sec Week](https://www.facebook.com/hashtag/code4sec) / Day 5 - Broken Access Control in JavaScript.
[#NEIS0736](https://www.facebook.com/hashtag/neis0736) [#NECS0736](https://www.facebook.com/hashtag/necs0736)

![JavaScript](/images/JS.gif)

## Using publicly writable directories is security-sensitive

Operating systems have global directories where any user has write access. Those folders are mostly used as temporary storage areas like /tmp in Linux based systems. An application manipulating files from these folders is exposed to race conditions on filenames: a malicious user can try to create a file with a predictable name before the application does. A successful attack can result in other files being accessed, modified, corrupted or deleted. This risk is even higher if the application runs with elevated permissions.

In the past, it has led to the following vulnerabilities:

* [CVE-2012-2451](https://nvd.nist.gov/vuln/detail/CVE-2012-2451)
* [CVE-2015-1838](https://nvd.nist.gov/vuln/detail/CVE-2015-1838)

This rule raises an issue whenever it detects a hard-coded path to a publicly writable directory like /tmp (see examples bellow). It also detects access to environment variables that point to publicly writable directories, e.g., TMP and TMPDIR.

* /tmp
* /var/tmp
* /usr/tmp
* /dev/shm
* /dev/mqueue
* /run/lock
* /var/run/lock
* /Library/Caches
* /Users/Shared
* /private/tmp
* /private/var/tmp
* \Windows\Temp
* \Temp
* \TMP

**Ask Yourself Whether**

* Files are read from or written into a publicly writable folder
* The application creates files with predictable names into a publicly writable folder
* There is a risk if you answered yes to any of those questions.

**Recommended Secure Coding Practices**

* Use a dedicated sub-folder with tightly controlled permissions
* Use secure-by-design APIs to create temporary files. Such API will make sure:
  * The generated filename is unpredictable
  * The file is readable and writable only by the creating user ID
  * The file descriptor is not inherited by child processes
  * The file will be destroyed as soon as it is closed

**Sensitive Code Example**
```
const fs = require('fs');

let tmp_file = "/tmp/temporary_file"; // Sensitive
fs.readFile(tmp_file, 'utf8', function (err, data) {
  // ...
});
```
```
const fs = require('fs');

let tmp_dir = process.env.TMPDIR; // Sensitive
fs.readFile(tmp_dir + "/temporary_file", 'utf8', function (err, data) {
  // ...
});
```

**Compliant Solution**

```
const tmp = require('tmp');

const tmpobj = tmp.fileSync(); // Compliant
```

**See**
* [OWASP Top 10 2017 Category A5](https://www.owasp.org/index.php/Top_10-2017_A5-Broken_Access_Control) - Broken Access Control
* [OWASP Top 10 2017 Category A3](https://www.owasp.org/index.php/Top_10-2017_A3-Sensitive_Data_Exposure) - Sensitive Data Exposure
* [MITRE, CWE-377](http://cwe.mitre.org/data/definitions/377) - Insecure Temporary File
* [MITRE, CWE-379](http://cwe.mitre.org/data/definitions/379) - Creation of Temporary File in Directory with Incorrect Permissions
* [OWASP, Insecure Temporary File](https://www.owasp.org/index.php/Insecure_Temporary_File)

**แหล่งที่มา**

[<img src="/images/SonarSourceRules.svg" alt="SonarQube" height="50">](https://rules.sonarsource.com/javascript/RSPEC-5443)
