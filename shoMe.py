import shodan
import textwrap
import re
import argparse
from sys import *
from ipaddress import IPv4Network

API_KEY = "ENTER API KEY HERE"
HIGH_PROFILE_PORTS = [21, 22, 23, 389, 445, 1443, 3306, 3389, 5432, 5432, 27017]
INTERESTING_TARGETS = []

def output_ip_port(outfile, lyst):
    outfile.write("#" * 70 + "\n")
    outfile.write("IP and Port information listed here: \n")
    for info in lyst:
        outfile.write(info + "\n")
    outfile.write("#" * 70 + "\n")

def output_webserver(outfile, lyst):
    outfile.write("Web server information listed here: \n")
    for webserv in lyst:
        #print(webserv)
        outfile.write(webserv + "\n")
    outfile.write("#" * 70 + "\n")

def output_vulns(outfile, lyst):
    outfile.write("Verified vulnerabilities listed here: \n")
    for vuln in lyst:
        outfile.write(vuln + "\n")
    outfile.write("#" * 70 + "\n")

def shoMe(option=None, infile, outfile):
    ip_port_list = []
    webserver_list = []
    vulns_list = []
    api = shodan.Shodan(API_KEY)
    with open(infile, "r") as ips:
        with open(outfile, "w") as out:
            for ip in ips:
                ret = "IP: "
                try:
                    info = api.host(ip, history=False)
                except:
                    continue
                for x in info["data"]:
                    if ("Server: Apache/" in x["data"]):
                        #print(str(x["data"]))
                        tmp= str(x["data"]).split("Server: Apache/")[1].split("\n")[0].replace("/", "").replace("\r", "")[0:14]
                        apache_result = "IP: {}; Apache Version: {}; Port: {} ".format(x['ip_str'], tmp, x['port'])
                        webserver_list.append(apache_result)
                    if ("Server: nginx/" in x["data"]):
                        tmp = str(x["data"]).split("Server: nginx/")[1].split("\n")[0].replace("/", "").replace("\r", "")
                        nginx_result = "IP: {}; Nginx Version: {}; Port: {} ".format(x['ip_str'], tmp, x['port'])
                        webserver_list.append(nginx_result)
                    if ("Server: Microsoft-IIS" in x["data"]):
                        tmp = str(x["data"]).split("Server: Microsoft-IIS")[1].split("\n")[0].replace("/", "").replace("\r", "")
                        iis_result = "IP: {}; IIS-Version: {}; Port: {} ".format(x['ip_str'], tmp, x['port'])
                        webserver_list.append(iis_result)
                    if ("X-Powered-By: PHP" in x['data']):
                        tmp = str(x["data"]).split("X-Powered-By: PHP")[1].split("\n")[0].replace("/", "").replace("\r", "")[0:6]
                        php_result = "IP: {}; PHP Version: {}; Port: {} ".format(x['ip_str'], tmp, x['port'])
                        webserver_list.append(php_result)
                    if ("Server: Apache-Coyote/" in x["data"]):
                        tmp = str(x["data"]).split("Server: Apache-Coyote/")[1].split("\n")[0].replace("/", "").replace("\r", "")
                        tomcat_result = "IP: {}; Coyote Version: {}; Port: {} ".format(x['ip_str'], tmp, x['port'])
                        webserver_list.append(tomcat_result)
                    if ("Server: lighttpd/" in x["data"]):
                        tmp = str(x["data"]).split("Server: lighttpd/")[1].split("\n")[0].replace("/", "").replace("\r", "")
                        lighttpd_result = "IP: {}; Lighttpd Version: {}; Port: {} ".format(x['ip_str'], tmp, x['port'])
                        webserver_list.append(lighttpd_result)
                    # Node.js is a bit of an edge case in the way it formats header data. Will have added soon
                    if ("vulns" in x.keys()):
                        tmp = x['vulns']
                        for k,v in tmp.items():
                            if (v['verified'] == True):
                                vulns = x['ip_str'] + ' ' + k + ' ' + str(v['verified'])
                                vulns_list.append(vulns)
                if (info != None):
                    ret += info['ip_str']
                    ret += "; Ports: "
                    p_ = info['ports']
                    for port in p_:
                        if port in HIGH_PROFILE_PORTS:
                            INTERESTING_TARGETS.append((info['ip_str'], port))
                        ret += str(port) +  ", "
                    ip_port_info = ret[:-2]
                    ip_port_list.append(ip_port_info)
                    info = None

            ip_port_list.sort()
            webserver_list.sort()
            vulns_list.sort()
            output_ip_port(out, ip_port_list)
            output_webserver(out, webserver_list)
            output_vulns(out, vulns_list)
            out.write("These IP addresses have interesting ports open: \n")
            for hv in INTERESTING_TARGETS:
                out.write("IP: {}; Port: {}".format(hv[0], hv[1]) + "\n")

if __name__ == '__main__':
    shoMe(argv[1], argv[2])
    # ArgParse stuff coming soon
    parser = argparse.ArgumentParser(add_help=True, description='A script for querying Shodan\'s API for interesting information useful for web application and external pentests', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('IP_file', help='A file of IP addresses you want to search Shodan for')
    parser.add_argument('--output', help='The name of the output file to write results to')
    parser.add_argument('--history', help='Shodan records a complete history of information on a given IP address. This flag enables the history to be gathered as well as current data')
    parser.add_argument('-a', '--all', help='')
    parser.add_argument('--vulns', help=)
    parser.add_argument('', help=)

    args = parser.parse_args()
