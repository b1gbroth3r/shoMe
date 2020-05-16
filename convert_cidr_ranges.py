import argparse
from ipaddress import IPv4Network


def converter(infile, outfile):
    
    with open(infile, "r") as cidrs:
        with open(outfile, "w") as ipfile:
            for rnge in cidrs:
                ip = rnge.strip("\n")
                if (ip == ""):
                    continue
                for i in IPv4Network(ip, False):
                    ipfile.write(str(i) + "\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="convert_cidr_ranges.py",
                                     description="Takes a file containing cidr ranges, creates file \
                of individual IPs within each range for shoMe script")
    parser.add_argument("--cidr-file", dest="cidr_file",
                        help="File containing CIDR ranges delimited by newline")
    parser.add_argument("--outfile", dest="outfile",
                        help="File to write results to")

    args = parser.parse_args()

    if (args.cidr_file == None or args.outfile == None):
        parser.print_help()
    else:
        print("[*] Expanding CIDR ranges...")
        converter(args.cidr_file, args.outfile)
        print("[!] IPs have been expanded to " + str(args.outfile))
        print("[*] You can now pass " + str(args.outfile) +
              " in shoMe.py with --ip-file")
