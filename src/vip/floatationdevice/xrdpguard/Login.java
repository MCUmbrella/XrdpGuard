package vip.floatationdevice.xrdpguard;

import java.text.SimpleDateFormat;
import java.util.Date;

public class Login
{
    private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
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
        return sdf.format(time) + "\t" + addr + "\t" + (fail ? "FAIL" : "SUCCESS");
    }
}
