using System;
using System.Runtime.InteropServices;

namespace DevolutionsAgent.Actions;

internal class Buffer : IDisposable
{
    public IntPtr Handle { get; }

    public Buffer(int size)
    {
        this.Handle = Marshal.AllocHGlobal(size);
    }

    public static implicit operator IntPtr(Buffer b) => b.Handle;

    private void ReleaseUnmanagedResources()
    {
        Marshal.FreeHGlobal(this.Handle);
    }

    public void Dispose()
    {
        ReleaseUnmanagedResources();
        GC.SuppressFinalize(this);
    }

    ~Buffer()
    {
        ReleaseUnmanagedResources();
    }
}
