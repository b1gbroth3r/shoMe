def write_results(results, outfile):
    with open(outfile, "w") as results_file:
        ip_and_port_results = results[0].sort()
        header_results = results[1].sort()
        verified_vulns_results = results[2].sort()

        results_file.write("#" * 20 + "IP/Port Results:" + "#" * 20 + "\n")
        for ipport in ip_and_port_results:
            results_file.write(str(ipport) + "\n")
        results_file.write("#" * 20 + "Server Headers Found: " + "#" * 20 + "\n")
        for headerr in header_results:
            results_file.write(str(headerr) + "\n")
        results_file.write("#" * 20 + "Verified Vulnerabilities: " + "#" * 20 + "\n")
        for vv in verified_vulns_results:
            results_file.write(str(vv) + "\n")