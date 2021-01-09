# Day 1 - Injection in JavaScript.

![JavaScript](/images/JS.gif)

## Formatting SQL queries is security-sensitive

Formatting strings used as SQL queries is security-sensitive. It has led in the past to the following vulnerabilities:

* [CVE-2018-9019](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9019)

* [CVE-2018-7318](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7318)

* [CVE-2017-5611](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5611)

SQL queries often need to use a hardcoded SQL string with a dynamic parameter coming from a user request. Formatting a string to add those parameters to the request is a bad practice as it can result in an SQL injection. The safe way to add parameters to a SQL query is to use SQL binding mechanisms.

**Ask Yourself Whether**

* the SQL query is built using string formatting technics, such as concatenating variables.
* some of the values are coming from an untrusted source and are not sanitized.

There is a risk if you answered yes to any of those questions.

**Recommended Secure Coding Practices**

* Avoid building queries manually using formatting technics. If you do it anyway, do not include user input in this building process.
* Use parameterized queries, prepared statements, or stored procedures whenever possible.
* You may also use ORM frameworks such as Hibernate which, if used correctly, reduce injection risks.
* Avoid executing SQL queries containing unsafe input in stored procedures or functions.
* Sanitize every unsafe input.

You can also reduce the impact of an attack by using a database account with low privileges.

**Sensitive Code Example**
```
// === MySQL ===
const mysql = require('mysql');
const mycon = mysql.createConnection({ host: host, user: user, password: pass, database: db });
mycon.connect(function(err) {
  mycon.query('SELECT * FROM users WHERE id = ' + userinput, (err, res) => {}); // Sensitive
});

// === PostgreSQL ===
const pg = require('pg');
const pgcon = new pg.Client({ host: host, user: user, password: pass, database: db });
pgcon.connect();
pgcon.query('SELECT * FROM users WHERE id = ' + userinput, (err, res) => {}); // Sensitive
```

**Compliant Solution**
```
// === MySQL ===
const mysql = require('mysql');
const mycon = mysql.createConnection({ host: host, user: user, password: pass, database: db });
mycon.connect(function(err) {
  mycon.query('SELECT name FROM users WHERE id = ?', [userinput], (err, res) => {});
});

// === PostgreSQL ===
const pg = require('pg');
const pgcon = new pg.Client({ host: host, user: user, password: pass, database: db });
pgcon.connect();
pgcon.query('SELECT name FROM users WHERE id = $1', [userinput], (err, res) => {});
```
**Exceptions**

This rule's current implementation does not follow variables. It will only detect SQL queries which are formatted directly in the function call.
```
const sql = 'SELECT * FROM users WHERE id = ' + userinput;
mycon.query(sql, (err, res) => {}); // Sensitive but no issue is raised.
```

**See**
* [OWASP Top 10 2017 Category A1](https://www.owasp.org/index.php/Top_10-2017_A1-Injection) - Injection
* [MITRE, CWE-89](http://cwe.mitre.org/data/definitions/89) - Improper Neutralization of Special Elements used in an SQL Command
* [MITRE, CWE-564](http://cwe.mitre.org/data/definitions/564.html) - SQL Injection: Hibernate
* [MITRE, CWE-20](http://cwe.mitre.org/data/definitions/20.html) - Improper Input Validation
* [MITRE, CWE-943](http://cwe.mitre.org/data/definitions/943.html) - Improper Neutralization of Special Elements in Data Query Logic
* [CERT, IDS00-J.](https://wiki.sei.cmu.edu/confluence/x/ITdGBQ) - Prevent SQL injection
* [SANS Top 25](https://www.sans.org/top25-software-errors/#cat1) - Insecure Interaction Between Components
* Derived from FindSecBugs rules [Potential SQL/JPQL Injection (JPA)](http://h3xstream.github.io/find-sec-bugs/bugs.htm#SQL_INJECTION_JPA), [Potential SQL/JDOQL Injection (JDO)](http://h3xstream.github.io/find-sec-bugs/bugs.htm#SQL_INJECTION_JDO), [Potential SQL/HQL Injection (Hibernate)](http://h3xstream.github.io/find-sec-bugs/bugs.htm#SQL_INJECTION_HIBERNATE)

**reference**

[<img src="/images/sonarqube.svg" alt="SonarQube" height="50">](https://rules.sonarsource.com/javascript/RSPEC-2077)
