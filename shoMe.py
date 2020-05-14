import argparse
import ipaddress
import platform
import logging
from os import getcwd

import shodan
from termcolor import colored

API_KEY = "XPSo6uKRSZfgsotuvEYTfXdIzRQJ08y6"
# TODO: Replace all prints with log


def print_results(results):
    ip_and_port_results = results[0]
    header_results = results[1]
    verified_vulns_results = results[2]
    
    ip_and_port_results.sort()
    header_results.sort()
    verified_vulns_results.sort()

    print("#" * 20 + "IP/Port Results " + "#" * 20)
    for ipport in ip_and_port_results:
        print(ipport)
    print("#" * 20 + "Server Headers Found " + "#" * 20)
    if (len(header_results) == 0):
        if (args.headers != None):
            print("No specified headers were found")
        else:
            print("You didn't specify the --header arg")
    for header in header_results:
        print(header)

    print("#" * 20 + "Verified Vulnerabilities " + "#" * 20)
    if (len(verified_vulns_results) == 0):
        if (args.vulns != False):
            print("No vulns were found on the IPs")
        else:
            print("You didn't specify the --vulns arg")
    for vv in verified_vulns_results:
        print(vv)


def write_results(results, outfile):
    with open(outfile, "w") as results_file:

        ip_and_port_results = results[0]
        header_results = results[1]
        verified_vulns_results = results[2]

        ip_and_port_results.sort()
        header_results.sort()
        verified_vulns_results.sort()

        results_file.write("#" * 20 + "IP/Port Results:" + "#" * 20 + "\n")
        for ipport in ip_and_port_results:
            results_file.write(str(ipport) + "\n")
        results_file.write(
            "#" * 20 + "Server Headers Found: " + "#" * 20 + "\n")
        if (len(header_results) == 0):
            if (args.headers != None):
                results_file.write("No headers were specified or found\n")
            else:
                results_file.write("You didn't specify the --header arg\n")
        for headerr in header_results:
            results_file.write(str(headerr) + "\n")
        results_file.write(
            "#" * 20 + "Verified Vulnerabilities: " + "#" * 20 + "\n")
        if (len(verified_vulns_results) == 0):
            if (args.vulns != False):
                results_file.write("No vulns were found on the IPs\n")
            else:
                results_file.write("You didn't specify the --vulns arg\n")
        for vv in verified_vulns_results:
            results_file.write(str(vv) + "\n")


def reporting_verified_vulns(x, lyst):
    tmp = x["vulns"]
    for k, v in tmp.items():
        if (v["verified"] == True):
            vulns = x["ip_str"] + " " + k + " " + str(v["verified"])
            lyst.append(vulns)


def retrieve_headers(header, x, lyst):
    tmp = str(x["data"]).split(header)[1].split(
        "\n")[0].replace("/", "").replace("\r", "")
    _result = "IP: {}; {} {}; Port: {} ".format(
        x['ip_str'], header, tmp, x['port'])
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
            ip_port_info = ret[:-2]
            ips_and_ports.append(ip_port_info)
            info = None
    return ips_and_ports, captured_headers, verified_vulns


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(
        prog="shoMe.py", description="Script to parse Shodan data")
    parser.add_argument("--IPs", nargs="*", dest="IPs",
                        help="IP Addresses to scan.")
    parser.add_argument("--ip-file", dest="ipfile",
                        help="File containing IPs delimited by a newline")
    parser.add_argument("--header", nargs="*", dest="headers",
                        help="Server headers to look for.")
    parser.add_argument("--vulns", dest="vulns", default=False,
                        help="Includes verified vulns associated with IPs")
    parser.add_argument("--history", dest="hist", default=False,
                        help="Option to include historical data for the IP being queried. Can significantly increase time to execute script.")
    parser.add_argument("--outfile", dest="outfile",
                        help="File to write results to")

    args = parser.parse_args()

    if (args.IPs != None):
        the_money = shoMe(args.IPs, args.headers, args.hist, args.vulns)
        if (args.outfile != None):
            write_results(the_money, args.outfile)
        else:
            print_results(the_money)
    elif (args.ipfile != None):
        addrs = []
        with open(args.ipfile, "r") as ipfile:
            for ip in ipfile:
                addrs.append(ip.strip())
        the_money = shoMe(addrs, args.headers, args.hist, args.vulns)
        if (args.outfile != None):
            write_results(the_money, args.outfile)
        else:
            print_results(the_money)
    else:
        parser.print_help()
