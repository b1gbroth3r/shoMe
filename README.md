# shoMe
Shoutout to @blurbdust for the idea and core code for this script!
A Python script that queries a list of IPs and returns useful or interesting information (for externals/webapps).

Example:
```python3 shoMe.py <file_of_IPs> <output_file>```

Example Output:
```
######################################################################
IP and Port information:
IP: 1.1.1.1; Ports: 80, 8080
IP: 2.2.2.2; Ports: 80, 443, 22
IP: 3.3.3.3; Ports: 80
######################################################################
Web server information:
IP: 1.1.1.1; Apache Version: 2.2.29 (Ubuntu); Port: 80
IP: 1.1.1.1; Lighttpd Version: 1.4.39; Port: 8080
IP: 2.2.2.2; IIS-Version: 7.5; Port: 80
IP: 2.2.2.2; Nginx Version: 1.16.1; Port: 443
IP: 3.3.3.3; PHP Version: 5.4.45; Port: 80
######################################################################
Verified vulnerabilities:
2.2.2.2 CVE-2015-1635 True
2.2.2.2 MS15-034 True
######################################################################
These IP addresses have interesting ports open:
IP: 2.2.2.2; Port 22
 ```

__Upcoming Additions__:
- [x] Additional webservers to look for
~~- [ ] Edge case for Node.js~~
- [ ] Possible threading support
- [ ] Write output to structured file to organize data into tables
- [ ] Support for CIDR notation
