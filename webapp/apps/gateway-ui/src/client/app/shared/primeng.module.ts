import { NgModule } from '@angular/core';

import { Accordion } from 'primeng/accordion';
import { ConfirmationService, MessageService } from 'primeng/api';
import { AutoComplete } from 'primeng/autocomplete';
import { Badge } from 'primeng/badge';
import { Button } from 'primeng/button';
import { DatePicker } from 'primeng/datepicker';
import { Card } from 'primeng/card';
import { Carousel } from 'primeng/carousel';
import { CheckboxModule } from 'primeng/checkbox';
import { ConfirmDialog } from 'primeng/confirmdialog';
import { ConfirmPopup } from 'primeng/confirmpopup';
import { ContextMenu } from 'primeng/contextmenu';
import { DataView } from 'primeng/dataview';
import { Dialog } from 'primeng/dialog';
import { Divider } from 'primeng/divider';
import { DomHandler } from 'primeng/dom';
import { Select } from 'primeng/select';
import { Fieldset } from 'primeng/fieldset';
import { FileUpload } from 'primeng/fileupload';
import { InputMask } from 'primeng/inputmask';
import { InputNumber } from 'primeng/inputnumber';
import { ToggleSwitch } from 'primeng/toggleswitch';
import { InputText } from 'primeng/inputtext';
import { Textarea } from 'primeng/textarea';
import { Listbox } from 'primeng/listbox';
import { Menu } from 'primeng/menu';
import { Message } from 'primeng/message';
import { MultiSelect } from 'primeng/multiselect';
import { OrderList } from 'primeng/orderlist';
import { Popover } from 'primeng/popover';
import { Panel } from 'primeng/panel';
import { PickList } from 'primeng/picklist';
import { ProgressSpinner } from 'primeng/progressspinner';
import { RadioButton } from 'primeng/radiobutton';
import { ScrollPanel } from 'primeng/scrollpanel';
import { SelectButton } from 'primeng/selectbutton';
import { Drawer } from 'primeng/drawer';
import { Slider } from 'primeng/slider';
import { SplitButton } from 'primeng/splitbutton';
import { Stepper } from 'primeng/stepper';
import { TableModule } from 'primeng/table';
import { Tabs, TabList, Tab, TabPanels, TabPanel } from 'primeng/tabs';
import { TieredMenu } from 'primeng/tieredmenu';
import { Toast } from 'primeng/toast';
import { ToggleButton } from 'primeng/togglebutton';
import { Toolbar } from 'primeng/toolbar';
import { Tooltip, TooltipModule } from 'primeng/tooltip';
import { Tree } from 'primeng/tree';
import { TreeTableModule } from 'primeng/treetable';
import { Scroller } from 'primeng/scroller';

const PRIMENG_MODULES = [
  Divider,
  Accordion,
  AutoComplete,
  Button,
  DatePicker,
  Card,
  Carousel,
  CheckboxModule,
  ContextMenu,
  DataView,
  Scroller,
  Dialog,
  Select,
  Fieldset,
  ConfirmDialog,
  FileUpload,
  InputMask,
  ToggleSwitch,
  Textarea,
  InputText,
  Listbox,
  Menu,
  Message,
  MultiSelect,
  OrderList,
  Popover,
  Panel,
  PickList,
  ProgressSpinner,
  RadioButton,
  ScrollPanel,
  SelectButton,
  Drawer,
  SplitButton,
  InputNumber,
  Stepper,
  TableModule,
  Tabs,
  TabList,
  Tab,
  TabPanels,
  TabPanel,
  TieredMenu,
  Toast,
  Toolbar,
  TooltipModule,
  ToggleButton,
  Tree,
  TreeTableModule,
  Badge,
  ConfirmPopup,
  Slider,
];

@NgModule({
  imports: PRIMENG_MODULES,
  exports: PRIMENG_MODULES,
  providers: [ConfirmationService, MessageService],
})
export class PrimeNgModules {
  constructor() {
    // https://github.com/primefaces/primeng/blob/ff9f8a2442da44f8ba00447b174f0d34e1c10e89/src/app/components/dialog/dialog.ts#L449
    Dialog.prototype.onResize = function (event: MouseEvent) {
      if (this.resizing) {
        const deltaX = event.pageX - this.lastPageX;
        const deltaY = event.pageY - this.lastPageY;
        const containerWidth = DomHandler.getOuterWidth(this.container);
        const containerHeight = DomHandler.getOuterHeight(this.container);
        const contentHeight = DomHandler.getOuterHeight(this.contentViewChild.nativeElement);
        const newWidth = containerWidth + deltaX;
        const newHeight = containerHeight + deltaY;
        const minWidth = this.container.style.minWidth;
        const minHeight = this.container.style.minHeight;
        const offset = DomHandler.getOffset(this.container);
        const viewport = DomHandler.getViewport();

        if ((!minWidth || newWidth > Number.parseInt(minWidth, 10)) && offset.left + newWidth < viewport.width) {
          this.container.style.width = newWidth + 'px';
        }

        if ((!minHeight || newHeight > Number.parseInt(minHeight, 10)) && offset.top + newHeight < viewport.height) {
          this.container.style.height = newHeight + 'px';
          this.contentViewChild.nativeElement.style.height = contentHeight + deltaY + 'px';
        }

        this.lastPageX = event.pageX;
        this.lastPageY = event.pageY;

        if (!event.shiftKey) {
          // Resize from center origin effect
          this.center();
        }
      }
    };

    // DEVSEC-578 Always escape tooltip content.
    Tooltip.prototype.updateText = function () {
      this.tooltipText.innerHTML = '';
      this.tooltipText.appendChild(document.createTextNode(this.getOption('tooltipLabel')));
    };
  }
}
