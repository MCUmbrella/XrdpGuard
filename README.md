```
Usage: java -jar XrdpGuard.jar [options]
Options:
    --help          Show the help message and exit.
    --log={}        Specify the path of XRDP log. (Default: /var/log/xrdp.log)
    --banlog={}     Specify the path of the file to save ban records to.
                    (Default: xrdpguard/ban.log)
    --whitelist={}  Specify the path of the file to load IP whitelist.
                    (Default: xrdpguard/whitelist.txt)
    --period={}     Specify the time period (in milliseconds) to consider for
                    login failures. (Default: 10 minutes)
    --maxfail={}    Specify the maximum number of login failures allowed before
                    an IP address is considered suspicious. (Default: 3)
    --firewall={}   Specify the firewall manager implementation class to use.
                    (Default: vip.floatationdevice.xrdpguard.firewall.Firewalld)
    --loop={}       Specify the interval (in milliseconds) between two checks.
                    A value less than 5000 means XRDPGaurd will check only once
                    and then exit. (Default: -1)
    --debug         Enable debug output.
    --dryrun        Perform a dry run: only show suspicious IP(s) and do not
                    modify the firewall.
    --export        Print the extracted login records to stdout and exit.
    --nobanlog      Do not save ban records. Overrides "--banlog={}"
```
Java 8 is required
