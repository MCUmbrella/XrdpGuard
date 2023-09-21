package vip.floatationdevice.xrdpguard;

import java.util.Date;

import static vip.floatationdevice.xrdpguard.XrdpGuardCommons.toXGTime;

public class LoginRecord
{
    public final Date time;
    public final String addr;
    public final boolean fail;

    public LoginRecord(Date time, String addr, boolean fail)
    {
        this.time = time;
        this.addr = addr;
        this.fail = fail;
    }

    public static LoginRecord build(Date time, String addr, boolean fail)
    {
        return new LoginRecord(time, addr, fail);
    }

    @Override
    public String toString()
    {
        return toXGTime(time) + "\t" + addr + "\t" + (fail ? "FAIL" : "SUCCESS");
    }
}
