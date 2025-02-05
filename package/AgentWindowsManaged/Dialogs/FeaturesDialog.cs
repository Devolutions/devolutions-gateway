using Microsoft.Deployment.WindowsInstaller;
using System;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using DevolutionsAgent.Resources;
using WixSharp;
using WixSharp.UI.Forms;
using View = System.Windows.Forms.View;

namespace DevolutionsAgent.Dialogs;

public partial class FeaturesDialog : AgentDialog
{
    FeatureItem[] features;

    public FeaturesDialog()
    {
        InitializeComponent();

        this.label1.MakeTransparentOn(banner);
        this.label2.MakeTransparentOn(banner);

        this.featuresTree.Columns.Clear();
        this.featuresTree.Columns.Add(string.Empty, -1, HorizontalAlignment.Left);
        this.featuresTree.Columns.Add(string.Empty, -1, HorizontalAlignment.Left);
        this.featuresTree.View = View.Details;
        this.featuresTree.HeaderStyle = ColumnHeaderStyle.None;
    }

    private void FeaturesDialog_Load(object sender, EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

        BuildFeaturesHierarchy();
    }

    private void BuildFeaturesHierarchy()
    {
        this.features = Runtime.Session.Features;
        
        FeatureItem[] rootItems = this.features.OrderBy(x => x.Title).ToArray();

        string[] addLocal = Runtime.Session["ADDLOCAL"].Split(',');
        string[] remove = Runtime.Session["REMOVE"].Split(',');

        foreach (FeatureItem rootItem in rootItems)
        {
            ListViewItem view = new ListViewItem
            {
                Text = rootItem.Title,
                Tag = rootItem
            };

            if (rootItem.DisallowAbsent)
            {
                view.ForeColor = SystemColors.GrayText;
                view.BackColor = SystemColors.InactiveBorder;
            }

            rootItem.View = view;

            if (addLocal.Contains(rootItem.Name))
            {
                view.Checked = true;
            }

            if (remove.Contains(rootItem.Name))
            {
                view.Checked = false;
            }

            if (rootItem.DisallowAbsent)
            {
                view.Checked = true;
            }

            if (Features.ExperimentalFeatures.Any(x => x.Id == rootItem.Name))
            {
                view.UseItemStyleForSubItems = false;
                view.SubItems.Add(I18n(Strings.ExperimentalLabel));
                view.SubItems[1].BackColor = Color.Yellow;
            }
        }

        rootItems.Where(x => x.Display != FeatureDisplay.hidden)
                 .Select(x => x.View)
                 .Cast<ListViewItem>()
                 .ForEach(featuresTree.Items.Add);

        this.featuresTree.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
    }

    private void Reset_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
    {
        features.ForEach(ResetViewChecked);
    }

    // ReSharper disable once RedundantOverriddenMember
    protected override void Back_Click(object sender, EventArgs e)
    {
        SaveUserSelection();

        base.Back_Click(sender, e);
    }

    // ReSharper disable once RedundantOverriddenMember
    protected override void Next_Click(object sender, EventArgs e)
    {
        SaveUserSelection();

        base.Next_Click(sender, e);
    }

    // ReSharper disable once RedundantOverriddenMember
    protected override void Cancel_Click(object sender, EventArgs e) => base.Cancel_Click(sender, e);

    private void SaveUserSelection()
    {
        Runtime.Session["ADDLOCAL"] = features
            .Where(IsViewChecked)
            .Select(x => x.Name)
            .JoinBy(",");

        Runtime.Session["REMOVE"] = features
            .Where(x => !IsViewChecked(x))
            .Select(x => x.Name)
            .JoinBy(",");
    }

    private void FeaturesTree_ItemCheck(object sender, ItemCheckEventArgs e)
    {
        if ((this.featuresTree.Items[e.Index].Tag as FeatureItem).DisallowAbsent)
        {
            e.NewValue = CheckState.Checked;
        }
    }

    private void FeaturesTree_SelectedIndexChanged(object sender, EventArgs e)
    {
        if (this.featuresTree.SelectedItems.Count == 0)
        {
            description.Text = string.Empty;
            return;
        }

        description.Text = (this.featuresTree.SelectedItems[0].Tag as FeatureItem).Description.LocalizeWith(Runtime.Localize);
    }

    private static bool IsViewChecked(FeatureItem feature)
    {
        return feature.View is ListViewItem {Checked: true};
    }

    private static void ResetViewChecked(FeatureItem feature)
    {
        if (feature.View is not ListViewItem item)
        {
            return;
        }

        item.Checked = DefaultIsToBeInstalled(feature);
    }

    private static bool DefaultIsToBeInstalled(FeatureItem feature)
    {
        return feature.RequestedState != InstallState.Absent;
    }
}
