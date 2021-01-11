# [Code4Sec Week](https://www.facebook.com/hashtag/code4sec) / Day 3 - Sensitive Data Exposure in JavaScript.
[#NEIS0736](https://www.facebook.com/hashtag/neis0736) [#NECS0736](https://www.facebook.com/hashtag/necs0736)

![JavaScript](/images/JS.gif)

## Using pseudorandom number generators (PRNGs) is security-sensitive

การสร้างค่าตัวเลขจาก pseudorandom มีความละเอียดอ่อนทางด้านความปลอดภัย ตัวอย่างช่องโหว่ที่เคยเกิดขึ้นในอดีตที่ผ่านมา

* [CVE-2013-6386](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-6386)
* [CVE-2006-3419](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3419)
* [CVE-2008-4102](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4102)

เมื่อซอฟต์แวร์ต้องพยายามสร้างตัวเลขที่คาดการณ์ไม่ได้จากค่าที่คาดการณ์ได้ มันจึงมีความเป็นไปได้ที่ผู้ไม่ประสงค์ดีจะสามารถคาดเดาค่าถัดไปที่ถูกสร้างได้และใช้การเดาค่านี้ในการสวมรอยเป็นผู้ใช้งานหรือเข้าถึงข้อมูลที่ละเอียดอ่อนได้

ดังนั้นฟังก์ชั่น Math.random() ก็ขึ้นอยู่กับ pseudorandom number generator ที่อ่อนแอ ฟังก์ชั่นนี้ไม่ควรใช้กับงานที่ต้องการความปลอดภัยสูง ๆ หรือใช้เพื่อปกป้องข้อมูลสำคัญ ดังนั้นจึงควรใช้ cryptographically strong pseudorandom number generator (CSPRNG) ทดแทนเพื่อความปลอดภัย

**ลองถามตัวเองดู**

* โค้ดมีการใช้ค่าที่ต้องการให้คาดเดาไม่ได้ เป็นกรณีของกลไกการเข้ารหัสทั้งหมดหรือเมื่อมีการแฮชค่าลับเช่นรหัสผ่าน
* ฟังก์ชั่นที่คุณใช้สร้างค่าสุ่มที่สามารถคาดการณ์ได้ (pseudo-random).
* ค่าสุ่มที่สร้างขึ้นมาถูกใช้ซ้ำหลาย ๆ ครั้ง
* ผู้ไม่ประสงค์ดีสามารถเข้าถึงค่าสุ่มที่ถูกสร้างขึ้นมาได้

มันคือความเสี่ยงหากคุณตอบใช่ในคำถามเหล่านี้

**คำแนะนำในการเขียน Code ให้ปลอดภัย**

* ใช้ cryptographically strong pseudorandom number generator (CSPRNG) เช่น crypto.getRandomValues().
* ใช้ค่าสุ่มที่ถูกสร้างเพียงครั้งเดียว.
* คุณไม่ควรเปิดเผยค่าสุ่มที่สร้างขึ้น ถ้าคุณจำเป็นต้องเก็บมันไว้ต้องให้มั่นใจว่าฐานข้อมูลหรือไฟล์นั้นถูกป้องกันอย่างดี

**ตัวอย่างที่ไม่ปลอดภัย**

```
const val = Math.random(); // Sensitive
// Check if val is used in a security context.
```

**แนวทางแก้ไขที่ถูกต้อง**

```
// === Client side ===
const crypto = window.crypto || window.msCrypto;
var array = new Uint32Array(1);
crypto.getRandomValues(array); // Compliant for security-sensitive use cases

// === Server side ===
const crypto = require('crypto');
const buf = crypto.randomBytes(1); // Compliant for security-sensitive use cases
```

**เพิ่มเติม**
* [OWASP Top 10 2017 Category A3](https://www.owasp.org/index.php/Top_10-2017_A3-Sensitive_Data_Exposure) - Sensitive Data Exposure
* [MITRE, CWE-338](http://cwe.mitre.org/data/definitions/338.html) - Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
* [MITRE, CWE-330](http://cwe.mitre.org/data/definitions/330.html) - Use of Insufficiently Random Values
* [MITRE, CWE-326](http://cwe.mitre.org/data/definitions/326.html) - Inadequate Encryption Strength
* [CERT, MSC02-J.](https://wiki.sei.cmu.edu/confluence/x/oTdGBQ) - Generate strong random numbers
* [CERT, MSC30-C.](https://wiki.sei.cmu.edu/confluence/x/UNcxBQ) - Do not use the rand() function for generating pseudorandom numbers
* [CERT, MSC50-CPP.](https://wiki.sei.cmu.edu/confluence/x/2ns-BQ) - Do not use std::rand() for generating pseudorandom numbers
* Derived from FindSecBugs rule [Predictable Pseudo Random Number Generator](http://h3xstream.github.io/find-sec-bugs/bugs.htm#PREDICTABLE_RANDOM)

**แหล่งที่มา**

[<img src="/images/sonarqube.svg" alt="SonarQube" height="50">](https://rules.sonarsource.com/javascript/RSPEC-2245)
