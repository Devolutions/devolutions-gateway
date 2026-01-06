using System;

namespace DevolutionsGateway.Helpers
{
    internal static class ErrorHelper
    {
        internal static Exception GetInnermostException(Exception ex)
        {
            if (ex is AggregateException ae)
            {
                ae = ae.Flatten();

                if (ae.InnerExceptions.Count == 1)
                {
                    ex = ae.InnerExceptions[0];
                }
                else
                {
                    return ae; // This would be unusual, but we return the flattened AggregateException itself.
                }
            }

            while (ex.InnerException != null)
            {
                ex = ex.InnerException;
            }

            return ex;
        }
    }
}
