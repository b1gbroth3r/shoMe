# Shoutout to @blurbdust for doing most of the legwork on this
import shodan
import textwrap
from sys import *

API_KEY = "ENTER YOUR API KEY HERE"
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

def shoMe(infile, outfile):
    ip_port_list = []
    webserver_list = []
    vulns_list = []
    with open(infile, "r") as ips:
        with open(outfile, "w") as out:
            for ip in ips:
                api = shodan.Shodan(API_KEY)
                ret = "IP: "
                try:
                    info = api.host(ip, history=False)
                except:
                    continue
                for x in info["data"]:
                    if ("Server: Microsoft-IIS" in x["data"]):
                        tmp = str(x["data"]).split("Server: Microsoft-IIS")[1].split("\n")[0].replace("/", "").replace("\r", "")
                        iis_result = "IP: {}; IIS-Version: {} ".format(x['ip_str'], tmp)
                        webserver_list.append(iis_result)
                    if ("X-Powered-By: PHP" in x['data']):
                        tmp = str(x["data"]).split("X-Powered-By: PHP")[1].split("\n")[0].replace("/", "").replace("\r", "")
                        php_result = "IP: {}; PHP Version: {} ".format(x['ip_str'], tmp)
                        webserver_list.append(php_result)
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
            output_ip_port(out, ip_port_list)
            output_webserver(out, webserver_list)
            output_vulns(out, vulns_list)
            out.write("These IP addresses have interesting ports open: \n")
            for hv in INTERESTING_TARGETS:
                out.write("IP: {}; Port: {}".format(hv[0], hv[1]) + "\n")

if __name__ == '__main__':
    shoMe(argv[1], argv[2])
