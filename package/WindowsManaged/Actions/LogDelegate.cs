using Microsoft.Deployment.WindowsInstaller;

namespace DevolutionsGateway.Actions;

internal interface ILogger
{
    void Log(string msg);

    void Log(string format, params object[] args);
}

internal class NullLogger : ILogger
{
    public void Log(string msg)
    {
    }

    public void Log(string format, params object[] args)
    {
    }
}

internal class LogDelegate : ILogger
{
    private readonly Session session;

    public LogDelegate(Session session)
    {
        this.session = session;
    }

    public static LogDelegate WithSession(Session session) => new(session);

    public void Log(string msg)
    {
        this.session?.Log(msg);
    }

    public void Log(string format, params object[] args)
    {
        this.session?.Log(format, args);
    }
}
