package vip.floatationdevice.xrdpguard;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.regex.Pattern;

public class XrdpGuardCommons
{
    private static final String VERSION = "0.4.0";
    private static final String HELP_MSG = "XRDPGuard version " + VERSION +
            "\nUsage: java -jar XrdpGuard.jar [options]\n" +
            "Options:\n" +
            "    --help          Show the help message and exit.\n" +
            "    --log={}        Specify the path of XRDP log. (Default: /var/log/xrdp.log)\n" +
            "    --banlog={}     Specify the path of the file to save ban records to.\n" +
            "                    (Default: xrdpguard/ban.log)\n" +
            "    --whitelist={}  Specify the path of the file to load IP whitelist.\n" +
            "                    (Default: xrdpguard/whitelist.txt)\n" +
            "    --period={}     Specify the time period (in milliseconds) to consider for\n" +
            "                    login failures. (Default: 10 minutes)\n" +
            "    --maxfail={}    Specify the maximum number of login failures allowed before\n" +
            "                    an IP address is considered suspicious. (Default: 3)\n" +
            "    --firewall={}   Specify the firewall manager implementation class to use.\n" +
            "                    (Default: vip.floatationdevice.xrdpguard.firewall.Firewalld)\n" +
            "    --loop={}       Specify the interval (in milliseconds) between two checks.\n" +
            "                    A value less than 5000 means XRDPGaurd will check only once\n" +
            "                    and then exit. (Default: -1)\n" +
            "    --debug         Enable debug output.\n" +
            "    --dryrun        Perform a dry run: only show suspicious IP(s) and do not\n" +
            "                    modify the firewall.\n" +
            "    --export        Print the extracted login records to stdout and exit.\n" +
            "    --nobanlog      Do not save ban records. Overrides \"--banlog={}\"";
    private static final SimpleDateFormat XRDP_TIME_FMT = new SimpleDateFormat("yyyyMMdd-HH:mm:ss");
    private static final SimpleDateFormat XG_TIME_FMT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
    private static final Pattern IPV4_PATTERN = Pattern.compile("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

    public static String getVersion(){return VERSION;}

    public static String getHelpMessage(){return HELP_MSG;}

    public static Date parseXRDPTime(String s)
    {
        try
        {
            return XRDP_TIME_FMT.parse(s);
        }
        catch(ParseException e)
        {
            throw new RuntimeException("Failed to parse XRDP time format \"" + s + "\": " + e);
        }
    }

    public static Date parseXGTime(String s)
    {
        try
        {
            return XG_TIME_FMT.parse(s);
        }
        catch(ParseException e)
        {
            throw new RuntimeException("Failed to parse XRDPGuard time format \"" + s + "\": " + e);
        }
    }

    public static String toXRDPTime(Date d)
    {
        return XRDP_TIME_FMT.format(d);
    }

    public static String toXRDPTime(long ms)
    {
        return XRDP_TIME_FMT.format(ms);
    }

    public static String toXGTime(Date d)
    {
        return XG_TIME_FMT.format(d);
    }

    public static String toXGTime(long ms)
    {
        return XG_TIME_FMT.format(ms);
    }

    public static boolean isIpv4(String s){return IPV4_PATTERN.matcher(s).matches();}
}
