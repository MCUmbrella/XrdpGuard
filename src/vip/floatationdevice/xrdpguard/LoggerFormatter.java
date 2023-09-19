package vip.floatationdevice.xrdpguard;

import java.text.SimpleDateFormat;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;

public class LoggerFormatter extends Formatter
{
    private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");

    @Override
    public String format(LogRecord record)
    {
        return "[" + sdf.format(record.getMillis()) + "] [" + record.getLevel() + "]\t" + record.getMessage() + "\n";
    }
}
