# shoMe

__Data gathered from this script does NOT actively scan any IP/range, it only queries the current state of the database for data gathered by the Shodan crawlers. This script should be used for passive OSINT data gathering during a pentest/red team engagement. Do not act on any information gathered from shoMe unless you have explicit consent from the owner(s) of the addresses.__

Shoutout to @blurbdust for the idea and core code for this script!
A Python script that queries a list of IPs and returns useful or interesting information (for externals/web-apps).
__Don't forget to add your API key at the top of the script, otherwise you'll get empty results.__

First, run pip3 install -r requirements.txt to ensure you have the necessary libraries.

The headers directory contains headers.txt, which lists common server headers to search for. Add/modify this list to suit your needs, and please feel free to ping me for suggestions on other server headers you think would be useful to search for.

The tests directory contains test_ips.txt. This file contains a list of random IP addresses that should report at least one occurrence of every header and at least one verified vulnerability.

If you have a file containing CIDR ranges separated by a newline, you can use the 
convert_cidr_ranges.py script to expand each range and write the IPs to a file to be passed into shoMe.py with the --ip-file argument.

```txt
Examples:
python3 shoMe.py --IPs 1.1.1.1 2.2.2.2 3.3.3.3
python3 shoMe.py --ip-file IPs.txt --outfile output.txt
python3 shoMe.py --ip-file IPs.txt --header "Server: nginx/"
python3 shoMe.py --IPs 1.1.1.1 2.2.2.2 --outfile output.txt --vulns
python3 shoMe.py --ip-file IPs.txt --all-headers --vulns
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

```txt
usage: shoMe.py [-h] [--IPs [IPS [IPS ...]]] [--ip-file IPFILE] [
                --header [HEADERS [HEADERS ...]]] [--all-headers ALLHEADS] 
                [--vulns VULNS] [--history HIST] [--outfile OUTFILE]

Script to parse Shodan data

optional arguments:
  -h, --help            show this help message and exit
  --IPs [IPS [IPS ...]]
                        IP Addresses to scan. (default: None)
  --ip-file IPFILE      File containing IPs delimited by a newline (default: None)
  --header [HEADERS [HEADERS ...]]
                        Server headers to look for. (default: None)
  --all-headers ALLHEADS
                        Load and search for all headers (default: None)
  --vulns VULNS         Includes verified vulns associated with IPs (default: False)
  --history HIST        Option to include historical data (default: False)
  --outfile OUTFILE     File to write results to (default: None)
```

__Upcoming Additions__:

- [ ] Write output to structured file to organize data into tables
