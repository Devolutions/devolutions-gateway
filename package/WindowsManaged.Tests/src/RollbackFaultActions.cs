using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using Microsoft.Deployment.WindowsInstaller;
using Newtonsoft.Json;
using WixSharp;
using File = System.IO.File;
using WixAction = WixSharp.Action;

namespace DevolutionsGateway.Actions
{
    // Copied into a separate installer source tree by New-RollbackFixture.ps1, never the production project.
    public static class RollbackFaultActions
    {
        public static WixAction[] Inject(WixAction[] actions)
        {
            return actions.Concat(new WixAction[]
            {
                Fault("LabFailAfterRemove", FailAfterRemove, Step.RemoveExistingProducts, "after-remove"),
                Fault("LabFailAfterService", FailAfterService, Step.InstallServices, "after-service"),
                Fault("LabFailAfterPermissions", FailAfterPermissions, new Step("CA.setUserDatabasePermissions"), "after-permissions"),
            }).ToArray();
        }

        private static ElevatedManagedAction Fault(string id, CustomActionMethod method, Step step, string phase)
        {
            return new ElevatedManagedAction(new Id(id), method, Return.check, When.After, step,
                new Condition($"NOT (REMOVE=\"ALL\") AND DGWLAB_FAILURE_PHASE=\"{phase}\""),
                Sequence.InstallExecuteSequence)
            {
                Execute = Execute.deferred,
                Impersonate = false,
                UsesProperties = "INSTALLDIR=[INSTALLDIR]",
            };
        }

        [CustomAction]
        public static ActionResult FailAfterRemove(Session session) => Fail(session, "after-remove");

        [CustomAction]
        public static ActionResult FailAfterService(Session session) => Fail(session, "after-service");

        [CustomAction]
        public static ActionResult FailAfterPermissions(Session session) => Fail(session, "after-permissions");

        private static ActionResult Fail(Session session, string phase)
        {
            bool serviceExists = false;
            bool markedForDeletion = false;
            string account = null;
            using (ServiceManager manager = new(WinAPI.SC_MANAGER_CONNECT, LogDelegate.WithSession(session)))
            {
                try
                {
                    if (Service.TryOpen(manager, "DevolutionsGateway", WinAPI.SERVICE_QUERY_CONFIG, out Service service))
                    {
                        using (service)
                        {
                            serviceExists = true;
                            account = service.GetAccountName();
                        }
                    }
                }
                catch (Win32Exception error) when (error.NativeErrorCode == 1072)
                {
                    markedForDeletion = true;
                }
            }

            string executable = Path.Combine(session.CustomActionData["INSTALLDIR"], "DevolutionsGateway.exe");
            string executableHash = null;
            if (File.Exists(executable))
            {
                using SHA256 hash = SHA256.Create();
                using FileStream stream = File.OpenRead(executable);
                executableHash = BitConverter.ToString(hash.ComputeHash(stream)).Replace("-", string.Empty);
            }

            string data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Devolutions", "Gateway");
            string dacl = Directory.Exists(data)
                ? Directory.GetAccessControl(data).GetSecurityDescriptorSddlForm(AccessControlSections.Access)
                : null;
            session.Log("DGWLAB_FAULT " + JsonConvert.SerializeObject(new
            {
                Phase = phase,
                ServiceExists = serviceExists,
                MarkedForDeletion = markedForDeletion,
                Account = account,
                ExecutableHash = executableHash,
                DataDacl = dacl,
            }));
            return ActionResult.Failure;
        }
    }
}
