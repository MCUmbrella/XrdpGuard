package vip.floatationdevice.xrdpguard;

import java.util.Date;

public class Login
{
    public final Date time;
    public final String addr;
    public final boolean fail;

    public Login(Date time, String addr, boolean fail)
    {
        this.time = time;
        this.addr = addr;
        this.fail = fail;
    }

    @Override
    public String toString()
    {
        return "[" + time + "] [" + addr + "]: " + (fail ? "FAIL" : "SUCCESS");
    }
}
