# [Code4Sec Week](https://www.facebook.com/hashtag/code4sec)
# Day 2 - Broken Authentication in JavaScript.
[#NEIS0736](https://www.facebook.com/hashtag/neis0736) [#NECS0736](https://www.facebook.com/hashtag/necs0736)

![JavaScript](/images/JS.gif)

## Hard-coded credentials are security-sensitive

Because it is easy to extract strings from an application source code or binary, credentials should not be hard-coded. This is particularly true for applications that are distributed or that are open-source.

In the past, it has led to the following vulnerabilities:

* CVE-2019-13466
* CVE-2018-15389

Credentials should be stored outside of the code in a configuration file, a database, or a management service for secrets.

This rule flags instances of hard-coded credentials used in database and LDAP connections. It looks for hard-coded credentials in connection strings, and for variable names that match any of the patterns from the provided list.

It's recommended to customize the configuration of this rule with additional credential words such as "oauthToken", "secret", ...

**Ask Yourself Whether**

Credentials allows access to a sensitive component like a database, a file storage, an API or a service.
Credentials are used in production environments.
Application re-distribution is required before updating the credentials.
There is a risk if you answered yes to any of those questions.

**Recommended Secure Coding Practices**

Store the credentials in a configuration file that is not pushed to the code repository.
Store the credentials in a database.
Use your cloud provider's service for managing secrets.
If the a password has been disclosed through the source code: change it.

**Sensitive Code Example**
```
var mysql = require('mysql');

var connection = mysql.createConnection(
{
  host:'localhost',
  user: "admin",
  database: "project",
  password: "mypassword", // sensitive
  multipleStatements: true
});

connection.connect();
```

**Compliant Solution**

```
var mysql = require('mysql');

var connection = mysql.createConnection({
  host: process.env.MYSQL_URL,
  user: process.env.MYSQL_USERNAME,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE
});
connection.connect();
```

**See**
* OWASP Top 10 2017 Category A2 - Broken Authentication
* MITRE, CWE-798 - Use of Hard-coded Credentials
* MITRE, CWE-259 - Use of Hard-coded Password
* CERT, MSC03-J. - Never hard code sensitive information
* SANS Top 25 - Porous Defenses
* Derived from FindSecBugs rule Hard Coded Password

**แหล่งที่มา**

[<img src="/images/sonarqube.svg" alt="SonarQube" height="50">](https://rules.sonarsource.com/javascript/RSPEC-2077)
