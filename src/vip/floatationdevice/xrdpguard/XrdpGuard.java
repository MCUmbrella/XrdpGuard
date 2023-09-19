package vip.floatationdevice.xrdpguard;

import vip.floatationdevice.xrdpguard.firewall.FirewallManager;
import vip.floatationdevice.xrdpguard.firewall.Firewalld;

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
    private static final Logger l = Logger.getLogger("XrdpGuard");
    private static final ArrayList<String> filteredLoginTimeAddr = new ArrayList<>();
    private static final ArrayList<Boolean> filteredLoginResult = new ArrayList<>();
    private static final ArrayList<Login> logins = new ArrayList<>();
    private static final SimpleDateFormat logDateFormat = new SimpleDateFormat("yyyyMMdd-HH:mm:ss");
    private static String logPath = "/var/log/xrdp.log"; // 默认日志路径
    private static long periodMs = 1 * 60 * 1000; // 默认时间跨度：1分钟
    private static int maxFails = 2; // 默认最多失败次数：2次
    private static FirewallManager fw;
    private static boolean flDebug = false;
    private static boolean flLoop = false;

    public static void main(String[] args) throws Exception
    {
        // 解析命令行参数（如果存在）
        // 带参数用法：XrdpGuard <日志路径> <时间跨度> <最大失败次数> [--debug]
        if(args.length >= 3)
        {
            logPath = args[0];
            periodMs = Long.parseLong(args[1]);
            maxFails = Integer.parseInt(args[2]);
            if(args.length > 3)
                for(int i = 3; i != args.length; i++)
                    if(args[i].equals("--debug"))
                        flDebug = true;
                    else if(args[i].equals("--loop"))
                        flLoop = true;
        }
        // 准备工作
        ConsoleHandler consoleHandler = new ConsoleHandler();
        consoleHandler.setFormatter(new LoggerFormatter());
        l.addHandler(consoleHandler);
        l.setUseParentHandlers(false);
        l.info("XRDPGuard is starting");
        if(flDebug)
        {
            consoleHandler.setLevel(Level.ALL);
            l.setLevel(Level.ALL);
            l.config("Enabled debug output");
        }
        l.config("Configurations:\n\tLog file path: " + logPath + "\n\tTime period (ms): " + periodMs + "\n\tMax fail count: " + maxFails);
        fw = new Firewalld();
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
            else if(line.contains("SSL_accept: I/O error")) // 客户端登录失败标志
            {
                filteredLoginResult.add(true);
            }
            else if(line.contains("] login successful")) // 客户端登录成功标志
            {
                filteredLoginResult.add(false);
            }
        }
        // 检查客户端连入次数和登录结果显示次数是否相同。如果不同，程序会报错并退出来避免错位导致的误判
        if(filteredLoginResult.size() == filteredLoginTimeAddr.size())
            l.info("Read available logins: " + filteredLoginTimeAddr.size());
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

//        // 调试信息
//        sb.setLength(0);
//        sb.append("Logins:\n\t");
//        for(Login l : logins)
//            sb.append(l.toString()).append("\n\t");
//        l.info(sb.toString());

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
        // 找到登录失败次数达到指定次数或更多的IP地址
        ArrayList<String> suspiciousIPs = new ArrayList<>();
        for(Map.Entry<String, Integer> entry : ipFailCounts.entrySet())
            if(entry.getValue() >= maxFails)
                suspiciousIPs.add(entry.getKey());
        // 输出符合条件的IP地址列表
        l.info("Suspicious IPs (" + suspiciousIPs.size() + "): " + suspiciousIPs);
        // 使用firewall-cmd命令添加富规则，丢弃来自所有此IP的连接
        // 注意：IP可能同时包含IPv4和IPv6，需要分别处理
        for(String ip : suspiciousIPs)
        {
            if(ip.indexOf(':') == -1) // IPv4
            {
                l.info("Ban IPv4: " + ip);
                if(fw.banIpv4(ip))
                    l.info("Banned IPv4 address: " + ip);
                else
                    l.warning("Failed to ban IPv4 address: " + ip);
            }
            else // IPv6
            {
                l.info("Ban IPv6: " + ip);
                if(fw.banIpv6(ip))
                    l.info("Banned IPv6 address: " + ip);
                else
                    l.warning("Failed to ban IPv6 address: " + ip);
            }
        }
        // 重载防火墙规则
        if(suspiciousIPs.size() != 0)
        {
            if(fw.apply())
                l.info("Firewall rule changes applied");
            else
                l.warning("Failed to apply firewall rule changes");
        }
        l.info("XRDPGuard is exiting");
    }
}
