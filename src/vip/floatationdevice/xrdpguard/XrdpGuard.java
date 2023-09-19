package vip.floatationdevice.xrdpguard;

import vip.floatationdevice.xrdpguard.firewall.FirewallManager;

import java.io.BufferedReader;
import java.io.FileReader;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

public class XrdpGuard
{
    private static final String VERSION = "0.1.0";
    private static final String HELP_MESSAGE = "XrdpGuard version " + VERSION +
            "\nUsage: java -jar XrdpGuard.jar [options]\n" +
            "Options:\n" +
            "    --help          Show the help message and exit.\n" +
            "    --log={}        Specify the path of XRDP log. (Default: /var/log/xrdp.log)\n" +
            "    --period={}     Specify the time period (in milliseconds) to consider for\n" +
            "                    login failures. (Default: 10 minutes)\n" +
            "    --maxFail={}    Specify the maximum number of login failures allowed before\n" +
            "                    an IP address is considered suspicious. (Default: 3)\n" +
            "    --impl={}       Specify the firewall manager implementation class to use.\n" +
            "                    (Default: vip.floatationdevice.xrdpguard.firewall.Firewalld)\n" +
            "    --debug         Enable debug output.\n" +
            "    --dryrun        Perform a dry run: only show suspicious IP(s) and do not\n" +
            "                    modify the firewall.\n" +
            "    --export        Print the extracted login records to stdout and exit.";
    private static final Logger l = Logger.getLogger("XrdpGuard");
    private static final ArrayList<String> filteredLoginTimeAddr = new ArrayList<>();
    private static final ArrayList<Boolean> filteredLoginResult = new ArrayList<>();
    private static final ArrayList<Login> logins = new ArrayList<>();
    private static final SimpleDateFormat logDateFormat = new SimpleDateFormat("yyyyMMdd-HH:mm:ss");
    private static String logPath = "/var/log/xrdp.log"; // 默认日志路径
    private static long periodMs = 10 * 60 * 1000; // 默认时间跨度：10分钟
    private static int maxFails = 3; // 默认最多失败次数：3次
    private static FirewallManager fw;
    private static String fwClassPath = "vip.floatationdevice.xrdpguard.firewall.Firewalld";
    private static boolean flDebug = false;
    private static boolean flDryRun = false;
    private static boolean flExportMode = false;

    public static void main(String[] args) throws Exception
    {
        // 解析命令行参数（如果存在）
        for(String a : args)
        {
            if(a.equals("--help")) // 打印帮助信息后退出
            {
                System.out.println(HELP_MESSAGE);
                System.exit(0);
            }
            else if(a.startsWith("--log=")) // 指定XRDP日志的路径
                logPath = a.substring(6);
            else if(a.startsWith("--period=")) // 设置时间范围（毫秒）
                periodMs = Long.parseLong(a.substring(9));
            else if(a.startsWith("--maxFail=")) // 设置时间范围内允许的最大登录失败次数
                maxFails = Integer.parseInt(a.substring(10));
            else if(a.startsWith("--impl=")) // 设置要使用的防火墙管理器类的路径
                fwClassPath = a.substring(7);
            else if(a.equals("--debug")) // 开启调试输出
                flDebug = true;
            else if(a.startsWith("--dryrun")) // 开启演练模式
                flDryRun = true;
            else if(a.startsWith("--export")) // 开启导出模式
                flExportMode = true;
        }

        // 准备工作
        ConsoleHandler consoleHandler = new ConsoleHandler();
        consoleHandler.setFormatter(new LoggerFormatter());
        l.addHandler(consoleHandler);
        l.setUseParentHandlers(false);
        l.info("XRDPGuard version " + VERSION);
        if(flDebug)
        {
            consoleHandler.setLevel(Level.ALL);
            l.setLevel(Level.ALL);
            l.config("Enabled debug output");
        }
        l.config("Configurations:\n\tLog file: " + logPath + "\n\tTime period (ms): " + periodMs + "\n\tMax fail count: " + maxFails + "\n\tFirewall manager: " + fwClassPath);
        fw = (FirewallManager) Class.forName(fwClassPath).newInstance();

        // 开始逐行读取日志
        l.fine("Reading " + logPath);
        BufferedReader br = new BufferedReader(new FileReader(logPath), 32768);
        StringBuilder sb = new StringBuilder();
        // xrdp.log中的客户端连入记录和登录成功记录不在同一行输出，所以需要至少两行才能判定登录是否成功
        String line;
        String lastIncomingConnectionLine = null;
        while(true)
        {
            line = br.readLine();
            if(line == null) // 检查是否读取到了文件末尾
            {
                // 如果到达了文件末尾，而且上条连入记录没有匹配到登录成功记录，将其标记为登录失败
                if(lastIncomingConnectionLine != null)
                {
                    filteredLoginTimeAddr.add(lastIncomingConnectionLine);
                    filteredLoginResult.add(true);
                }
                break;
            }
            // 首先检测日志开始标志。程序将从最后遇到的日志开始标志处开始扫描
            if(line.contains("starting xrdp"))
            {
                // 检测到新的日志开头，前面的记录作废
                filteredLoginTimeAddr.clear();
                filteredLoginResult.clear();
                lastIncomingConnectionLine = null;
            }
            // 检查客户端连入标志
            else if(line.contains("connection received from"))
            {
                if(lastIncomingConnectionLine != null)
                {
                    // 上条连入记录没有匹配到登录成功记录，将其标记为登录失败
                    filteredLoginTimeAddr.add(lastIncomingConnectionLine);
                    filteredLoginResult.add(true);
                }
                // 更新上条连入记录为此次记录
                sb.setLength(0);
                sb.append(line, 1, 18).append(' ').append(line, line.indexOf("from ") + 5, line.indexOf(" port"));
                lastIncomingConnectionLine = sb.toString();
            }
            // 检查客户端登录成功标志
            else if(line.contains("] login succ"))
            {
                if(lastIncomingConnectionLine == null)
                    continue;
                // 存在上条连入记录且匹配到了登录成功记录，将其标记为登录成功
                filteredLoginTimeAddr.add(lastIncomingConnectionLine);
                filteredLoginResult.add(false);
                lastIncomingConnectionLine = null;
            }
        }
        // 检查客户端连入次数和登录结果显示次数是否相同。如果不同，程序会报错并退出来避免错位导致的误判
        if(filteredLoginResult.size() == filteredLoginTimeAddr.size())
            l.fine("Read available logins: " + filteredLoginTimeAddr.size());
        else
        {
            l.severe("ArrayList entry count mismatch! filteredLoginTimeAddr.size(): " + filteredLoginTimeAddr.size() + ", filteredLoginResult.size(): " + filteredLoginResult.size());
            System.exit(-1);
        }
        // 将两个列表中的记录合并为一个Login列表
        for(int i = 0; i != filteredLoginTimeAddr.size(); i++)
        {
            String[] s = filteredLoginTimeAddr.get(i).split(" ");
            logins.add(new Login(
                    logDateFormat.parse(s[0]),
                    s[1],
                    filteredLoginResult.get(i)
            ));
        }
        filteredLoginTimeAddr.clear();
        filteredLoginResult.clear();

        // 导出模式：将从日志中提取出的登录记录打印到标准输出
        if(flExportMode)
        {
            l.info("Exporting login records to stdout");
            sb.setLength(0);
            for(Login login : logins)
                sb.append(login.toString()).append('\n');
            System.out.print(sb);
            l.info("Exported " + logins.size() + " records");
            System.exit(0);
        }

        // 创建一个Map来统计每个IP地址的失败登录次数
        HashMap<String, Integer> ipFailCounter = new HashMap<>();
        // 获取当前时间
        Date now = new Date();
        // 遍历登录记录
        for(Login login : logins)
        {
            // 计算登录记录的时间与当前时间的差距
            long timeDiff = now.getTime() - login.time.getTime();
            // 如果时间差在时间跨度内且登录失败，更新IP地址的失败计数
            if(timeDiff <= periodMs && login.fail)
                ipFailCounter.put(login.addr, ipFailCounter.getOrDefault(login.addr, 0) + 1);
        }
        logins.clear();
        // 找到登录失败次数达到指定次数或更多的IP地址
        ArrayList<String> suspiciousIPs = new ArrayList<>();
        for(Map.Entry<String, Integer> entry : ipFailCounter.entrySet())
            if(entry.getValue() >= maxFails)
                suspiciousIPs.add(entry.getKey());
        ipFailCounter.clear();
        // 输出符合条件的IP地址列表
        l.info("Suspicious IPs (" + suspiciousIPs.size() + "): " + suspiciousIPs);

        // 演练模式：只输出将要被封禁的IP，不执行实际操作
        if(flDryRun)
        {
            l.info("Dry run completed");
            System.exit(0);
        }

        // 使用实现FirewallManager接口的类来封禁IP
        // 注意：IP可能同时包含IPv4和IPv6，需要分别处理
        int bannedIpCount = 0;
        for(String ip : suspiciousIPs)
        {
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
        // 重载防火墙规则
        if(bannedIpCount != 0)
        {
            if(fw.apply())
                l.info("Firewall rule changes applied");
            else
                l.warning("Failed to apply firewall rule changes");
        }
        l.info("Completed: " + bannedIpCount + " IP(s) banned");
    }
}
