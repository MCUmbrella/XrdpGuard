```
Usage: java -jar XrdpGuard.jar [options]
Options:
    --help          Show the help message and exit.
    --log={}        Specify the path of XRDP log. (Default: /var/log/xrdp.log)
    --period={}     Specify the time period (in milliseconds) to consider for
                    login failures. (Default: 10 minutes)
    --maxFail={}    Specify the maximum number of login failures allowed before
                    an IP address is considered suspicious. (Default: 3)
    --impl={}       Specify the firewall manager implementation class to use.
                    (Default: vip.floatationdevice.xrdpguard.firewall.Firewalld)
    --debug         Enable debug output.
    --dryrun        Perform a dry run: only show suspicious IP(s) and do not
                    modify the firewall.
    --export        Print the extracted login records to stdout and exit.
```
Java 8 is required
