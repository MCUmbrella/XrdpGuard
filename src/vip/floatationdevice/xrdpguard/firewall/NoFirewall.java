package vip.floatationdevice.xrdpguard.firewall;

/**
 * 不执行任何实际的防火墙操作的假防火墙管理器。
 */
public class NoFirewall implements FirewallManager
{
    @Override
    public boolean banIpv4(String ip)
    {
        return true;
    }

    @Override
    public boolean banIpv6(String ip)
    {
        return true;
    }

    @Override
    public boolean unbanIpv4(String ip)
    {
        return true;
    }

    @Override
    public boolean unbanIpv6(String ip)
    {
        return true;
    }

    @Override
    public boolean isBannedIpv4(String ip)
    {
        return false;
    }

    @Override
    public boolean isBannedIpv6(String ip)
    {
        return false;
    }

    @Override
    public boolean apply()
    {
        return true;
    }
}
