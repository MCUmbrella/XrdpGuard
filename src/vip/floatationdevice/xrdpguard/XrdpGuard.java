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
        // 带参数用法：XrdpGuard [--log=日志路径] [--period=时间跨度] [--maxFail=最大失败次数] [--impl=防火墙管理类路径] [--debug] [--dryrun]
        for(String a : args)
        {
            if(a.equals("--help"))
            {
                System.out.println("XrdpGuard [--log={}] [--period={}] [--maxFail={}] [--impl={}] [--debug] [--dryrun] [--export]");
                System.exit(0);
            }
            else if(a.startsWith("--log="))
                logPath = a.substring(6);
            else if(a.startsWith("--period="))
                periodMs = Long.parseLong(a.substring(9));
            else if(a.startsWith("--maxFail="))
                maxFails = Integer.parseInt(a.substring(10));
            else if(a.startsWith("--impl="))
                fwClassPath = a.substring(7);
            else if(a.equals("--debug"))
                flDebug = true;
            else if(a.startsWith("--dryrun"))
                flDryRun = true;
            else if(a.startsWith("--export"))
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
        l.fine("Reading " + logPath);
        BufferedReader br = new BufferedReader(new FileReader(logPath), 32768);
        String line;
        StringBuilder sb = new StringBuilder();
        // 开始逐行读取日志
        while((line = br.readLine()) != null)
        {
            // 首先检测日志开始标志。程序将从最后遇到的日志开始标志处开始扫描
            if(line.contains("starting xrdp"))
            {
                // 检测到新的日志开头，前面的记录作废
                filteredLoginTimeAddr.clear();
                filteredLoginResult.clear();
            }
            // 按日志条目类型把客户端连入记录和登录结果记录分别存储，因为两种记录不在同一行输出
            if(line.contains("connection received from")) // 客户端连入标志
            {
                sb.setLength(0);
                sb.append(line, 1, 18).append(' ').append(line, line.indexOf("from ") + 5, line.indexOf(" port"));
                filteredLoginTimeAddr.add(sb.toString());
            }
            else if(line.contains("] login fail") ||
                    line.contains("SSL_accept: I/O error") ||
                    line.contains("libxrdp_force_read: header read error")
            ) // 客户端登录失败标志
            {
                filteredLoginResult.add(true);
            }
            else if(line.contains("] login succ")) // 客户端登录成功标志
            {
                filteredLoginResult.add(false);
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
        HashMap<String, Integer> ipFailCounts = new HashMap<>();
        // 获取当前时间
        Date now = new Date();
        // 遍历登录记录
        for(Login login : logins)
        {
            // 计算登录记录的时间与当前时间的差距
            long timeDiff = now.getTime() - login.time.getTime();
            // 如果时间差在时间跨度内且登录失败，更新IP地址的失败计数
            if(timeDiff <= periodMs && login.fail)
                ipFailCounts.put(login.addr, ipFailCounts.getOrDefault(login.addr, 0) + 1);
        }
        logins.clear();
        // 找到登录失败次数达到指定次数或更多的IP地址
        ArrayList<String> suspiciousIPs = new ArrayList<>();
        for(Map.Entry<String, Integer> entry : ipFailCounts.entrySet())
            if(entry.getValue() >= maxFails)
                suspiciousIPs.add(entry.getKey());
        ipFailCounts.clear();
        // 输出符合条件的IP地址列表
        l.info("Suspicious IPs (" + suspiciousIPs.size() + "): " + suspiciousIPs);

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
