import shodan
import argparse
import ipaddress
import platform
import headers
from os import getcwd
from termcolor import colored

API_KEY = "RZi6tB6WtGjo3japnXzUACEzzBIs5uuB"

def shoMe(ip_addresses, headers, history, vulns):
    api = shodan.Shodan(API_KEY)
    for ip in ip_addresses:
        ret = "IP: "
        try:
            info = api.host(ip, history=history)
        except:
            continue
        for x in info["data"]:
            if (vulns and "vulns" in x.keys()):
                tmp = x["vulns"]
                for k,v in tmp.items():
                    if (v["verified"] == True):
                        vulns = x["ip_str"] + " " + k + " " + str(v["verified"])
                        print(vulns)
            #if (headers != None and headers in x["data"]):
        if (info != None):
            ret += info["ip_str"]
            ret += "; Ports: "
            p_ = info["ports"]
            for port in p_:
                ret += str(port) + ", "
            print(ret)
            info = None

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
    print(args)

    if (args.IPs != None):
        shoMe(args.IPs, args.headers, args.hist, args.vulns)
    elif (args.ipfile != None):
        print("Hello")
    else:
        parser.print_help()