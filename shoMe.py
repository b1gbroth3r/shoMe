import shodan
import argparse
import ipaddress
from os import getcwd
from termcolor import colored

API_KEY = "ZxIrBuTLSdeLdwNMrASJxiDiWDbBrNes"
HIGH_PROFILE_PORTS = [20, 21, 22, 23, 88, 107, 115, 137, 139, 161, 389, 445, 623, 1443, 3306, 3389, 5432, 5432, 5900, 
                      27017]
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
                    if ("X-AspNet-Version: " in x["data"]):
                        tmp = str(x["data"]).split("X-AspNet-Version: ")[1].split("\n")[0].replace("/", "").replace("\r", "")
                        asp_dot_net_result = "IP: {}; ASP.Net Version: {}; Port: {} ".format(x['ip_str'], tmp, x['port'])
                        webserver_list.append(asp_dot_net_result)
                    if ("Server: Apache-Coyote/" in x["data"]):
                        tmp = str(x["data"]).split("Server: Apache-Coyote/")[1].split("\n")[0].replace("/", "").replace("\r", "")
                        tomcat_result = "IP: {}; Coyote Version: {}; Port: {} ".format(x['ip_str'], tmp, x['port'])
                        webserver_list.append(tomcat_result)
                    if ("Server: lighttpd/" in x["data"]):
                        tmp = str(x["data"]).split("Server: lighttpd/")[1].split("\n")[0].replace("/", "").replace("\r", "")
                        lighttpd_result = "IP: {}; Lighttpd Version: {}; Port: {} ".format(x['ip_str'], tmp, x['port'])
                        webserver_list.append(lighttpd_result)
                    if ("SERVER: node.js/" in x["data"]):
                        tmp = str(x["data"]).split("SERVER: node.js/")[1].split("\n")[0].replace("/", "").replace("\r", "")[0:6]
                        node_js_result = "IP: {}; Node.js Version: {}; Port: {} ".format(x['ip_str'], tmp, x['port'])
                        webserver_list.append(node_js_result)
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
    parser = argparse.ArgumentParser(prog='shoMe.py', description="Script for parsing Shodan data")
    parser.add_argument('ips', nargs="*", help="IP addresses to scan")
    parser.add_argument('outfile', help="File to write results to")
    parser.add_argument('--ip_file', help="File of individual IP addresses delimited by newlines")
    parser.add_argument('--cidr_file', dest='cidr_file', help="File of CIDR IP ranges delimited by newlines")

    args = parser.parse_args()
    
    if (args.ips != None and not args.ip_file and not args.cidr_file):
        try:
            print(colored("[!] Processing CIDR ranges.", "blue", attrs=['bold']))
            with open("cidr_ips.txt", "w") as cidr:
                IP = args.ips
                for i in IP:
                    for j in ipaddress.IPv4Network(i):
                        cidr.write(str(j) + "\n")
            print(colored("[+] CIDR ranges processed and are being queried...", "yellow", attrs=['bold']))
            cwd = getcwd()
            path = cwd + '/cidr_ips.txt'
            shoMe(path, args.outfile)
            print(colored("[+] All IPs have been queried! Check {} for the results".format(args.outfile), "green", attrs=['bold']))
        except:
            print(colored("[!] Error: Please check typos and make sure arguments are correct", "red", attrs=['bold']))

    if (args.ip_file != None):
        try:
            print(colored("[+] Loading file containing IP addresses", "yellow", attrs=['bold']))
            shoMe(args.ip_file, args.outfile)
            print(colored("[+] All IP addresses have been queried! Check {} for the results".format(args.outfile), "cyan", attrs=['bold']))
        except:
            print(colored("[!] Error: Please check typos and contents of the ip file for errors", "red", attrs=['bold']))

    elif (args.cidr_file):
        try:
            print(colored("[+] Loading file containing CIDR ranges", "blue", attrs=['bold']))
            with open(args.cidr_file, "r") as cidr:
                with open("cidr_to_ips.txt", "w") as cidr_to_ip:
                    for rng in cidr:
                        ip = rng.strip("\n")
                        for i in ipaddress.IPv4Network(ip):
                            cidr_to_ip.write(str(i) + "\n")
            print(colored("[+] All IPs within the ranges are processed. Querying Shodan now...", "yellow", attrs=['bold']))
            cwd = getcwd()
            path = cwd + '/cidr_to_ips.txt'
            shoMe(path, args.outfile)
            print(colored("[+] All IPs within the CIDR ranges have been queried! Check {} for the results".format(args.outfile), "green", attrs=['bold']))
        except:
            print(colored("[!] Error: Please check typos and contents of the CIDR file for errors", "red", attrs=['bold']))
