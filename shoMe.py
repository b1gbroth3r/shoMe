import argparse
import ipaddress
import platform
from os import getcwd

import shodan
from termcolor import colored

import assist

API_KEY = "ENTER API KEY"

def reporting_verified_vulns(x, lyst):
    tmp = x["vulns"]
    for k,v in tmp.items():
        if (v["verified"] == False):
            vulns = x["ip_str"] + " " + k + " " + str(v["verified"])
            lyst.append(vulns)

def retrieve_headers(header, x, lyst):
    tmp = str(x["data"]).split(header)[1].split("\n")[0].replace("/", "").replace("\r", "")
    _result = "IP: {}; {} {}; Port: {} ".format(x['ip_str'], header, tmp, x['port'])
    lyst.append(_result)

def shoMe(ip_addresses, headers, history, vulns):
    verified_vulns = []
    captured_headers = []
    ips_and_ports = []
    api = shodan.Shodan(API_KEY)
    for ip in ip_addresses:
        ret = "IP: "
        try:
            info = api.host(ip, history=history)
        except:
            continue
        for x in info["data"]:
            if (vulns and "vulns" in x.keys()):
                reporting_verified_vulns(x, verified_vulns)
            if (headers != None):
                for header in headers:
                    if (header in x["data"]):
                        retrieve_headers(header, x, captured_headers)
        if (info != None):
            ret += info["ip_str"]
            ret += "; Ports: "
            p_ = info["ports"]
            for port in p_:
                ret += str(port) + ", "
            ips_and_ports.append(ret)
            info = None
    return ips_and_ports, captured_headers, verified_vulns

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="shoMe.py", description="Script to parse Shodan data")
    parser.add_argument("--IPs", nargs="*", dest="IPs", help="IP Addresses to scan.")
    parser.add_argument("--ip-file", dest="ipfile", help="File containing IPs delimited by a newline")
    parser.add_argument("--header", nargs="*", dest="headers", help="Server headers to look for.")
    parser.add_argument("--vulns", dest="vulns", default=False, help="Includes verified vulns associated with IPs")
    parser.add_argument("--history", dest="hist", default=False,
        help="Option to include historical data for the IP being queried. Can significantly increase time to execute script.")
    parser.add_argument("--outfile", dest="outfile", help="File to write results to")

    args = parser.parse_args()
    
    if (args.IPs != None):
        the_money = shoMe(args.IPs, args.headers, args.hist, args.vulns)
        if (args.outfile != None):
            assist.write_results(the_money, args.outfile)
    elif (args.ipfile != None):
        addrs = []
        with open(args.ipfile, "r") as ipfile:
            for ip in ipfile:
                addrs.append(ip.strip())
        the_money = shoMe(addrs, args.headers, args.hist, args.vulns)
        if (args.outfile != None):
            assist.write_results(the_money, args.outfile)
        
    else:
        parser.print_help()
