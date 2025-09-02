using Microsoft.Deployment.WindowsInstaller;
using System;
using System.Collections.Generic;
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
    private FeatureItem[] features;

    private readonly ImageList imageList = new ImageList();

    public FeaturesDialog()
    {
        InitializeComponent();
        this.label1.MakeTransparentOn(banner);
        this.label2.MakeTransparentOn(banner);

        this.imageList.ImageSize = new Size(1, 20);

        this.featuresTree.Columns.Clear();
        this.featuresTree.Columns.Add(string.Empty, -1, HorizontalAlignment.Left);
        this.featuresTree.Columns.Add(string.Empty, -1, HorizontalAlignment.Left);
        this.featuresTree.View = View.Details;
        this.featuresTree.HeaderStyle = ColumnHeaderStyle.None;
        this.featuresTree.SmallImageList = this.imageList;
    }

    private void FeaturesDialog_Load(object sender, EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

        BuildFeaturesHierarchy();
    }

    private ListViewItem CreateFeatureListItem(FeatureItem featureItem, bool addLocal, bool remove, int level = 0)
    {
        ListViewItem view = new ListViewItem
        {
            Text = featureItem.Title,
            Tag = featureItem
        };

        featureItem.View = view;

        if (addLocal)
        {
            view.Checked = true;
        }

        if (remove)
        {
            view.Checked = false;
        }

        if (featureItem.DisallowAbsent)
        {
            view.Checked = true;
            view.ForeColor = SystemColors.GrayText;
        }

        if (Features.ExperimentalFeatures.Any(x => x.Id == featureItem.Name))
        {
            view.UseItemStyleForSubItems = false;
            view.SubItems.Add(I18n(Strings.ExperimentalLabel));
            view.SubItems[1].BackColor = Color.Yellow;
        }

        view.IndentCount = level * 10;

        return view;
    }

    private void BuildFeaturesHierarchy()
    {
        this.features = Runtime.Session.Features;

        string[] addLocal = Runtime.Session["ADDLOCAL"].Split(',');
        string[] remove = Runtime.Session["REMOVE"].Split(',');

        List<FeatureItem> featureItems = new();

        foreach (FeatureItem featureItem in this.features.OrderBy(x => x.Title).Where(x => x.Parent is null))
        {
            if (!featureItem.ParentName.IsEmpty())
            {
                continue;
            }

            featureItem.View = CreateFeatureListItem(featureItem, addLocal.Contains(featureItem.Name), remove.Contains(featureItem.Name));
            featureItems.Add(featureItem);

            foreach (FeatureItem childFeature in this.features.Where(x => x.ParentName == featureItem.Name))
            {
                childFeature.View = CreateFeatureListItem(childFeature, addLocal.Contains(childFeature.Name), remove.Contains(childFeature.Name), level: 1);
                featureItems.Add(childFeature);
            }
        }

        featureItems.Where(x => x.Display != FeatureDisplay.hidden)
                 .Select(x => x.View)
                 .Cast<ListViewItem>()
                 .ForEach(featuresTree.Items.Add);

        this.featuresTree.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
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
}
