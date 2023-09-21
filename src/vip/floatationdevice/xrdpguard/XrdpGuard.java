package vip.floatationdevice.xrdpguard;

import vip.floatationdevice.xrdpguard.firewall.FirewallManager;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import java.util.logging.Formatter;
import java.util.logging.*;

import static vip.floatationdevice.xrdpguard.XrdpGuardCommons.*;

public class XrdpGuard
{
    private static String xrdpLogPath = "/var/log/xrdp.log"; // 默认XRDP日志路径
    private static long periodMs = 10 * 60 * 1000; // 默认时间跨度：10分钟
    private static int maxFails = 3; // 默认最多失败次数：3次
    private static String fwClassPath = "vip.floatationdevice.xrdpguard.firewall.Firewalld";
    private static boolean flDebug = false;
    private static boolean flDryRun = false;
    private static boolean flExportMode = false;
    private static long loopMs = -1; //TODO

    public static void main(String[] args)
    {
        // 准备工作
        Logger l;
        FirewallManager fw;
        Set<String> whitelist = null;
        List<LoginRecord> logins;
        List<String> suspiciousIPs;
        int bannedIpCount = 0;
        parseArgs(args);
        l = setupLogger();
        l.info("XRDPGuard version " + getVersion());
        l.config("Enabled debug output");
        l.config("Configurations:\n\tLog file: " + xrdpLogPath + "\n\tTime period (ms): " + periodMs + "\n\tMax fail count: " + maxFails + "\n\tFirewall manager: " + fwClassPath);
        // 创建防火墙管理器类的实例
        try
        {
            fw = (FirewallManager) Class.forName(fwClassPath).newInstance();
        }
        catch(InstantiationException | IllegalAccessException | ClassNotFoundException e)
        {
            throw new RuntimeException("Failed to create instance of \"" + fwClassPath + "\": " + e, e);
        }

        // 读取IP白名单（xrdpguard/whitelist.txt）
        l.fine("Reading whitelist");
        try
        {
            whitelist = loadWhitelist();
            l.fine("Whitelist (" + whitelist.size() + "): " + whitelist);
        }
        catch(Exception e)
        {
            l.warning("Failed to load whitelist: " + e);
        }

        // 开始逐行读取日志
        l.fine("Reading " + xrdpLogPath);
        logins = loadXrdpLog(xrdpLogPath);
        l.fine("Read " + logins.size() + " login records");

        // 如果是导出模式，将日志中提取出的登录记录打印到标准输出后退出
        if(flExportMode)
        {
            l.info("Exporting login records to stdout");
            StringBuilder sb = new StringBuilder();
            for(LoginRecord login : logins)
                sb.append(login.toString()).append('\n');
            System.out.print(sb);
            l.info("Exported " + logins.size() + " records");
            System.exit(0);
        }

        // 检查可疑IP并输出
        long nowMs = System.currentTimeMillis();
        l.fine("Checking suspicious IPs");
        l.fine("Check from " + toXGTime(nowMs - periodMs) + " to " + toXGTime(nowMs));
        suspiciousIPs = checkSuspiciousIps(logins, nowMs, periodMs);
        l.info("Suspicious IPs (" + suspiciousIPs.size() + "): " + suspiciousIPs);

        // 如果是演练模式，输出可疑IP后退出
        if(flDryRun)
        {
            l.info("Dry run completed");
            System.exit(0);
        }

        // 使用实现FirewallManager接口的类来封禁IP
        // 注意：IP可能同时包含IPv4和IPv6，需要分别处理
        for(String ip : suspiciousIPs)
        {
            if(whitelist != null && whitelist.contains(ip))
                continue;
            if(ip.indexOf(':') == -1) // IPv4
            {
                if(fw.isBannedIpv4(ip))
                    continue;
                l.fine("Ban IPv4 " + ip);
                if(fw.banIpv4(ip))
                {
                    l.info("Banned IPv4 address: " + ip);
                    ++bannedIpCount;
                }
                else
                    l.warning("Failed to ban IPv4 address: " + ip);
            }
            else // IPv6
            {
                if(fw.isBannedIpv6(ip))
                    continue;
                l.fine("Ban IPv6 " + ip);
                if(fw.banIpv6(ip))
                {
                    l.info("Banned IPv6 address: " + ip);
                    ++bannedIpCount;
                }
                else
                    l.warning("Failed to ban IPv6 address: " + ip);
            }
        }

        // 应用防火墙规则
        if(bannedIpCount != 0)
        {
            if(fw.apply())
                l.fine("Firewall rule changes applied");
            else
                l.warning("Failed to apply firewall rule changes");
        }

        l.info("Completed: " + bannedIpCount + " IP(s) banned");
    }

    private static void parseArgs(String[] args)
    {
        for(String a : args)
        {
            if(a.equals("--help")) // 打印帮助信息后退出
            {
                System.out.println(getHelpMessage());
                System.exit(0);
            }
            else if(a.startsWith("--log=")) // 指定XRDP日志的路径
                xrdpLogPath = a.substring(6);
            else if(a.startsWith("--period=")) // 设置时间范围（毫秒）
                periodMs = Long.parseLong(a.substring(9));
            else if(a.startsWith("--maxfail=")) // 设置时间范围内允许的最大登录失败次数
                maxFails = Integer.parseInt(a.substring(10));
            else if(a.startsWith("--firewall=")) // 设置要使用的防火墙管理器类的路径
                fwClassPath = a.substring(11);
            else if(a.equals("--debug")) // 开启调试输出
                flDebug = true;
            else if(a.startsWith("--dryrun")) // 开启演练模式
                flDryRun = true;
            else if(a.startsWith("--export")) // 开启导出模式
                flExportMode = true;
        }
    }

    private static Logger setupLogger()
    {
        Logger l = Logger.getLogger("XrdpGuard");
        ConsoleHandler h = new ConsoleHandler();
        h.setFormatter(new Formatter()
        {
            @Override
            public String format(LogRecord r)
            {
                return "[" + toXGTime(r.getMillis()) + "] [" + r.getLevel() + "]\t" + r.getMessage() + "\n";
            }
        });
        l.addHandler(h);
        l.setUseParentHandlers(false);
        if(flDebug)
        {
            h.setLevel(Level.ALL);
            l.setLevel(Level.ALL);
        }
        return l;
    }

    private static Set<String> loadWhitelist() throws IOException
    {
        Set<String> whitelist = new HashSet<>();
        BufferedReader br = new BufferedReader(new FileReader(getWhitelistFile()));
        String line;
        while((line = br.readLine()) != null)
            whitelist.add(line);
        return whitelist;
    }

    private static List<LoginRecord> loadXrdpLog(String path)
    {
        List<LoginRecord> logins = new LinkedList<>();
        BufferedReader br;
        try
        {
            br = new BufferedReader(new FileReader(path));
        }
        catch(FileNotFoundException e)
        {
            throw new RuntimeException("XRDP log not found: " + path, e);
        }
        // xrdp.log中的客户端连入记录和登录成功记录不在同一行输出，所以需要至少两行才能判定登录是否成功
        String line;
        Date lastIncomingConnectionTime = null;
        String lastIncomingConnectionIp = null;
        while(true)
        {
            try
            {
                line = br.readLine();
            }
            catch(IOException e)
            {
                throw new RuntimeException("XRDP log read failure: " + e, e);
            }
            if(line == null) // 检查是否读取到了文件末尾
            {
                // 如果到达了文件末尾，而且上条连入记录没有匹配到登录成功记录，将其标记为登录失败
                if(lastIncomingConnectionIp != null)
                    logins.add(LoginRecord.build(lastIncomingConnectionTime, lastIncomingConnectionIp, true));
                break;
            }
            // 首先检测日志开始标志。程序将从最后遇到的日志开始标志处开始扫描
            if(line.contains("starting xrdp"))
            {
                // 检测到新的日志开头，前面的记录作废
                logins.clear();
                lastIncomingConnectionTime = null;
                lastIncomingConnectionIp = null;
            }
            // 检查客户端连入标志
            else if(line.contains("connection received from"))
            {
                if(lastIncomingConnectionIp != null)
                    // 上条连入记录没有匹配到登录成功记录，将其标记为登录失败
                    logins.add(LoginRecord.build(lastIncomingConnectionTime, lastIncomingConnectionIp, true));
                // 更新上条连入记录为此次记录
                lastIncomingConnectionTime = XrdpGuardCommons.parseXRDPTime(line.substring(1, 18));
                lastIncomingConnectionIp = line.substring(line.indexOf("from ") + 5, line.indexOf(" port"));
            }
            // 检查客户端登录成功标志
            else if(line.contains("] login succ"))
            {
                if(lastIncomingConnectionIp == null)
                    continue;
                // 存在上条连入记录且匹配到了登录成功记录，将其标记为登录成功
                logins.add(LoginRecord.build(lastIncomingConnectionTime, lastIncomingConnectionIp, false));
                lastIncomingConnectionTime = null;
                lastIncomingConnectionIp = null;
            }
        }
        return logins;
    }

    private static List<String> checkSuspiciousIps(List<LoginRecord> logins, long nowMs, long periodMs)
    {
        List<String> suspiciousIPs = new LinkedList<>(); // 记录时间跨度内登录失败次数达到指定次数或更多的IP地址
        HashMap<String, Integer> ipFailCounter = new HashMap<>(); // 每个IP地址的失败登录次数
        // 遍历登录记录
        for(LoginRecord login : logins)
        {
            // 计算登录记录的时间与当前时间的差距
            long timeDiff = nowMs - login.time.getTime();
            // 如果时间差在时间跨度内且登录失败，增加此IP地址的失败计数
            if(timeDiff <= periodMs && login.fail)
                ipFailCounter.put(login.addr, ipFailCounter.getOrDefault(login.addr, 0) + 1);
        }
        // 找到并记录登录失败次数达到指定次数或更多的IP地址
        for(Map.Entry<String, Integer> entry : ipFailCounter.entrySet())
            if(entry.getValue() >= maxFails)
                suspiciousIPs.add(entry.getKey());
        return suspiciousIPs;
    }
}
