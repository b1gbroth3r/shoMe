import shoMe

apache = "Server: Apache/"
nginx = "Server: nginx/"
iis = "Server: Microsoft-IIS"
php = "X-Powered-By: PHP"
asp = "X-AspNet-Version: "
coyote = "Server: Apache-Coyote/"
lighttpd = "Server: lighttpd/"
node = "SERVER: node.js/"

def vulns():
    if (vulns and "vulns" in x.keys()):
        tmp = x["vulns"]
        for k,v in tmp.items():
            if (v["verified"] == True):
                vulns = x["ip_str"] + " " + k + " " + str(v["verified"])
                print(vulns) 