# shoMe

Shoutout to @blurbdust for the idea and core code for this script!
A Python script that queries a list of IPs and returns useful or interesting information (for externals/web-apps).
__Don't forget to add your API key at the top of the script, otherwise you'll get empty results.__

If you have a file containing CIDR ranges separated by a newline, you can use the 
convert_cidr_ranges.py script to expand each range and write the IPs to a file to be passed into shoMe.py with the --ip-file argument.

```python3
Examples:
python3 shoMe.py --IPs 1.1.1.1 2.2.2.2 3.3.3.3
python3 shoMe.py --ip-file IPs.txt --outfile output.txt
python3 shoMe.py --ip-file IPs.txt --header "Server: nginx/"
python3 shoMe.py --IPs 1.1.1.1 2.2.2.2 --outfile output.txt --vulns True
```

```txt
Example Output:
######################################################################
IP and Port information:
IP: 1.1.1.1; Ports: 80, 8080
IP: 2.2.2.2; Ports: 80, 443, 22
IP: 3.3.3.3; Ports: 80
######################################################################
Server Headers Found:
IP: 1.1.1.1; Apache Version: 2.2.29 (Ubuntu); Port: 80
IP: 1.1.1.1; Lighttpd Version: 1.4.39; Port: 8080
IP: 2.2.2.2; IIS-Version: 7.5; Port: 80
IP: 2.2.2.2; Nginx Version: 1.16.1; Port: 443
IP: 3.3.3.3; PHP Version: 5.4.45; Port: 80
######################################################################
Verified Vulnerabilities:
2.2.2.2 CVE-2015-1635 True
2.2.2.2 MS15-034 True
```

```python3
usage: shoMe.py [-h] [--IPs [IPS [IPS ...]]] [--ip-file IPFILE]
                [--header [HEADERS [HEADERS ...]]] [--vulns VULNS]
                [--history HIST] [--outfile OUTFILE]

Script to parse Shodan data

optional arguments:
  -h, --help            show this help message and exit
  --IPs [IPS [IPS ...]]
                        IP Addresses to scan.
  --ip-file IPFILE      File containing IPs delimited by a newline
  --header [HEADERS [HEADERS ...]]
                        Server headers to look for.
  --vulns VULNS         Includes verified vulns associated with IPs
  --history HIST        Option to include historical data for the IP being
                        queried. Can significantly increase time to execute
                        script.
  --outfile OUTFILE     File to write results to
```

__Upcoming Additions__:

- [x] Additional web servers to look for
- [ ] Support for CIDR notation
- [ ] Write output to structured file to organize data into tables
