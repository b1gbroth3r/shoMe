# Shoutout to @blurbdust for doing most of the legwork on this
import shodan
import textwrap
from sys import *


API_KEY = "API KEY GOES HERE"
HIGH_PROFILE_PORTS = [21, 22, 23, 389, 445, 1443, 3306, 3389, 5432, 5432, 27017]
INTERESTING_TARGETS = []

def shoMe(infile, outfile):
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
                        out.write(iis_result + "\n")
                    if ("X-Powered-By: PHP" in x['data']):
                        tmp = str(x["data"]).split("X-Powered-By: PHP")[1].split("\n")[0].replace("/", "").replace("\r", "")
                        php_result = "IP: {}; PHP Version: {} ".format(x['ip_str'], tmp)
                        out.write(php_result + "\n")
                    if ("vulns" in x.keys()):
                        print("IP: {} HAS VULNS".format(x['ip_str']))
                        # TODO Figure out a way to traverse the nested dictionaries and pull out only vulns that are listed as verified
                if (info != None):
                    ret += info['ip_str']
                    ret += "; Ports: "
                    p_ = info['ports']
                    for port in p_:
                        if port in HIGH_PROFILE_PORTS:
                            INTERESTING_TARGETS.append((info['ip_str'], port))
                        ret += str(port) +  ", "
                    out.write(ret[:-2] + "\n")
                    info = None

            out.write("These IP addresses have interesting ports open: \n")
            for hv in INTERESTING_TARGETS:
                out.write("IP: {}; Port: {}".format(hv[0], hv[1]) + "\n")

if __name__ == '__main__':
    shoMe(argv[1], argv[2])
