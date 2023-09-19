package vip.floatationdevice.xrdpguard.firewall;

/**
 * 防火墙管理器接口，包含一系列IP封禁相关的函数。
 */
public interface FirewallManager
{
    /**
     * 封禁指定的IPv4地址。
     * @param ip 需要封禁的IP。
     * @return 如果成功，返回true，否则返回false。
     */
    boolean banIpv4(String ip);

    /**
     * 封禁指定的IPv6地址。
     * @param ip 需要封禁的IP。
     * @return 如果成功，返回true，否则返回false。
     */
    boolean banIpv6(String ip);

    /**
     * 解除指定IPv4地址的封禁。
     * @param ip 要解除封禁的IP。
     * @return 如果成功，返回true，否则返回false。
     */
    boolean unbanIpv4(String ip);

    /**
     * 解除指定IPv6地址的封禁。
     * @param ip 要解除封禁的IP。
     * @return 如果成功，返回true，否则返回false。
     */
    boolean unbanIpv6(String ip);

    /**
     * 检查IPv4地址是否已被封禁。
     * @param ip 要检查的IP。
     * @return 如果IP已被封禁，返回true，否则返回false。
     */
    boolean isBannedIpv4(String ip);

    /**
     * 检查IPv6地址是否已被封禁。
     * @param ip 要检查的IP。
     * @return 如果IP已被封禁，返回true，否则返回false。
     */
    boolean isBannedIpv6(String ip);

    /**
     * 应用对防火墙规则的更改。
     * 某些防火墙软件（如firewalld）可能需要手动应用更改，所以设置此函数来统一标准。
     * 如果对防火墙规则的更改是实时生效的，此函数应该始终返回true。
     * @return 如果成功，返回true，否则返回false。
     */
    boolean apply();
}
