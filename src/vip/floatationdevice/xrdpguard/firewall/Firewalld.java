package vip.floatationdevice.xrdpguard.firewall;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * 基于firewalld和执行系统命令实现FirewallManager接口。
 * 使用firewall-cmd命令进行富规则操作，通过丢弃指定IP数据包的方式来实现IP封禁。
 */
public class Firewalld implements FirewallManager
{
    private static final Logger l = Logger.getLogger("XrdpGuard");
    private static final Pattern ipv4Pattern = Pattern.compile("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");


    public Firewalld()
    {
        l.config("Firewall manager implementation: " + getClass().getName());
    }

    @Override
    public boolean banIpv4(String ip)
    {
        return system("firewall-cmd --add-rich-rule='rule family=ipv4 source address=" + ip + " drop' --permanent");
    }

    @Override
    public boolean banIpv6(String ip)
    {
        // 如果是嵌入IPv6的IPv4地址（如::ffff:217.76.50.132），提取并交给处理IPv4的函数
        if(ip.startsWith("::ffff:") && isIpv4(ip.substring(7)))
            return banIpv4(ip.substring(7));
        return system("firewall-cmd --add-rich-rule='rule family=ipv6 source address=" + ip + " drop' --permanent");
    }

    @Override
    public boolean unbanIpv4(String ip)
    {
        return system("firewall-cmd --remove-rich-rule='rule family=ipv4 source address=" + ip + " drop' --permanent");
    }

    @Override
    public boolean unbanIpv6(String ip)
    {
        if(ip.startsWith("::ffff:") && isIpv4(ip.substring(7)))
            return unbanIpv4(ip.substring(7));
        return system("firewall-cmd --remove-rich-rule='rule family=ipv6 source address=" + ip + " drop' --permanent");
    }

    @Override
    public boolean isBannedIpv4(String ip)
    {
        return system("firewall-cmd --query-rich-rule='rule family=ipv4 source address=" + ip + " drop'");
    }

    @Override
    public boolean isBannedIpv6(String ip)
    {
        if(ip.startsWith("::ffff:") && isIpv4(ip.substring(7)))
            return isBannedIpv4(ip.substring(7));
        return system("firewall-cmd --query-rich-rule='rule family=ipv6 source address=" + ip + " drop'");
    }

    @Override
    public boolean apply()
    {
        return system("firewall-cmd --reload");
    }

    /**
     * 使用bash执行系统命令。
     * @param cmd 需要执行的命令。
     * @return 如果命令返回值为0，返回true，否则返回false。
     */
    private boolean system(String cmd)
    {
        try
        {
            l.fine("[cmd] Executing: " + cmd);
            Process proc = new ProcessBuilder("/bin/bash", "-c", cmd).start();
            BufferedReader stdout = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            BufferedReader stderr = new BufferedReader(new InputStreamReader(proc.getErrorStream()));
            String output;
            while((output = stdout.readLine()) != null)
                l.fine("[cmd] [stdout] " + output);
            while((output = stderr.readLine()) != null)
                l.fine("[cmd] [stderr] " + output);
            int exitCode = proc.waitFor();
            l.fine("[cmd] Command exited with code " + exitCode);
            return exitCode == 0;
        }
        catch(IOException | InterruptedException e)
        {
            l.severe("[cmd] Error occurred while executing " + cmd);
            l.severe("[cmd] Cause: " + e);
            e.printStackTrace();
            return false;
        }
    }

    private static boolean isIpv4(String s)
    {
        return ipv4Pattern.matcher(s).matches();
    }
}
