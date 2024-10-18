using DevolutionsAgent.Dialogs;
using System;
using System.Linq;
using WixSharp;

namespace WixSharpSetup.Dialogs;

public partial class MaintenanceTypeDialog : AgentDialog
{
    public MaintenanceTypeDialog()
    {
        InitializeComponent();

        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);
    }

    Type ProgressDialog
    {
        get
        {
            return Shell.Dialogs
                .FirstOrDefault(d => d.GetInterfaces().Contains(typeof(IProgressDialog)));
        }
    }

    void change_Click(object sender, System.EventArgs e)
    {
        Runtime.Session["MODIFY_ACTION"] = "Change";
        Shell.GoNext();
    }

    void repair_Click(object sender, System.EventArgs e)
    {
        Runtime.Session["MODIFY_ACTION"] = "Repair";
        int index = Shell.Dialogs.IndexOf(ProgressDialog);
        if (index != -1)
            Shell.GoTo(index);
        else
            Shell.GoNext();
    }

    void remove_Click(object sender, System.EventArgs e)
    {
        Runtime.Session["REMOVE"] = "ALL";
        Runtime.Session["MODIFY_ACTION"] = "Remove";

        int index = Shell.Dialogs.IndexOf(ProgressDialog);
        if (index != -1)
            Shell.GoTo(index);
        else
            Shell.GoNext();
    }

    // ReSharper disable once RedundantOverriddenMember
    protected override void Back_Click(object sender, EventArgs e) => base.Back_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Next_Click(object sender, EventArgs e) => base.Next_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Cancel_Click(object sender, EventArgs e) => base.Cancel_Click(sender, e);

    public override void OnLoad(object sender, System.EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

        base.OnLoad(sender, e);
    }
}
