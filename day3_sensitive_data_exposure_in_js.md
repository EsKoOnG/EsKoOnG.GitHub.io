# [Code4Sec Week](https://www.facebook.com/hashtag/code4sec) / Day 3 - Sensitive Data Exposure in JavaScript.
[#NEIS0736](https://www.facebook.com/hashtag/neis0736) [#NECS0736](https://www.facebook.com/hashtag/necs0736)

![JavaScript](/images/JS.gif)

## Using pseudorandom number generators (PRNGs) is security-sensitive

Using pseudorandom number generators (PRNGs) is security-sensitive. For example, it has led in the past to the following vulnerabilities:

* CVE-2013-6386
* CVE-2006-3419
* CVE-2008-4102

When software generates predictable values in a context requiring unpredictability, it may be possible for an attacker to guess the next value that will be generated, and use this guess to impersonate another user or access sensitive information.

As the Math.random() function relies on a weak pseudorandom number generator, this function should not be used for security-critical applications or for protecting sensitive data. In such context, a cryptographically strong pseudorandom number generator (CSPRNG) should be used instead.

**Ask Yourself Whether**

* the code using the generated value requires it to be unpredictable. It is the case for all encryption mechanisms or when a secret value, such as a password, is hashed.
* the function you use generates a value which can be predicted (pseudo-random).
* the generated value is used multiple times.
* an attacker can access the generated value.

There is a risk if you answered yes to any of those questions.

**Recommended Secure Coding Practices**

Use a cryptographically strong pseudorandom number generator (CSPRNG) like crypto.getRandomValues().
Use the generated random values only once.
You should not expose the generated random value. If you have to store it, make sure that the database or file is secure.

**Sensitive Code Example**

```
const val = Math.random(); // Sensitive
// Check if val is used in a security context.
```

**Compliant Solution**

```
// === Client side ===
const crypto = window.crypto || window.msCrypto;
var array = new Uint32Array(1);
crypto.getRandomValues(array); // Compliant for security-sensitive use cases

// === Server side ===
const crypto = require('crypto');
const buf = crypto.randomBytes(1); // Compliant for security-sensitive use cases
```

**See**
* OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
* MITRE, CWE-338 - Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
* MITRE, CWE-330 - Use of Insufficiently Random Values
* MITRE, CWE-326 - Inadequate Encryption Strength
* CERT, MSC02-J. - Generate strong random numbers
* CERT, MSC30-C. - Do not use the rand() function for generating pseudorandom numbers
* CERT, MSC50-CPP. - Do not use std::rand() for generating pseudorandom numbers
* Derived from FindSecBugs rule Predictable Pseudo Random Number Generator

**แหล่งที่มา**

[<img src="/images/sonarqube.svg" alt="SonarQube" height="50">](https://rules.sonarsource.com/javascript/RSPEC-2245)
