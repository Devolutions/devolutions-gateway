import { NgModule } from '@angular/core';

import { AccordionModule } from 'primeng/accordion';
import { ConfirmationService, MessageService } from 'primeng/api';
import { AutoCompleteModule } from 'primeng/autocomplete';
import { BadgeModule } from 'primeng/badge';
import { ButtonModule } from 'primeng/button';
import { CardModule } from 'primeng/card';
import { CarouselModule } from 'primeng/carousel';
import { CheckboxModule } from 'primeng/checkbox';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { ConfirmPopupModule } from 'primeng/confirmpopup';
import { ContextMenuModule } from 'primeng/contextmenu';
import { DataViewModule } from 'primeng/dataview';
import { DatePickerModule } from 'primeng/datepicker';
import { Dialog, DialogModule } from 'primeng/dialog';
import { DividerModule } from 'primeng/divider';
import { DomHandler } from 'primeng/dom';
import { DrawerModule } from 'primeng/drawer';
import { FieldsetModule } from 'primeng/fieldset';
import { FileUploadModule } from 'primeng/fileupload';
import { InputMaskModule } from 'primeng/inputmask';
import { InputNumberModule } from 'primeng/inputnumber';
import { InputTextModule } from 'primeng/inputtext';
import { ListboxModule } from 'primeng/listbox';
import { MenuModule } from 'primeng/menu';
import { MessageModule } from 'primeng/message';
import { MultiSelectModule } from 'primeng/multiselect';
import { OrderListModule } from 'primeng/orderlist';
import { PanelModule } from 'primeng/panel';
import { PickListModule } from 'primeng/picklist';
import { PopoverModule } from 'primeng/popover';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { RadioButtonModule } from 'primeng/radiobutton';
import { ScrollPanelModule } from 'primeng/scrollpanel';
import { SelectModule } from 'primeng/select';
import { SelectButtonModule } from 'primeng/selectbutton';
import { SliderModule } from 'primeng/slider';
import { SplitButtonModule } from 'primeng/splitbutton';
import { StepsModule } from 'primeng/steps';
import { TableModule } from 'primeng/table';
import { TabsModule } from 'primeng/tabs';
import { TextareaModule } from 'primeng/textarea';
import { TieredMenuModule } from 'primeng/tieredmenu';
import { ToastModule } from 'primeng/toast';
import { ToggleButtonModule } from 'primeng/togglebutton';
import { ToggleSwitch } from 'primeng/toggleswitch';
import { ToolbarModule } from 'primeng/toolbar';
import { Tooltip, TooltipModule } from 'primeng/tooltip';
import { TreeModule } from 'primeng/tree';
import { TreeTableModule } from 'primeng/treetable';

const PRIMENG_MODULES = [
  DividerModule,
  AccordionModule,
  AutoCompleteModule,
  ButtonModule,
  DatePickerModule,
  CardModule,
  CarouselModule,
  CheckboxModule,
  ContextMenuModule,
  DataViewModule,
  DialogModule,
  SelectModule,
  FieldsetModule,
  ConfirmDialogModule,
  FieldsetModule,
  FileUploadModule,
  InputMaskModule,
  ToggleSwitch,
  TextareaModule,
  InputTextModule,
  ListboxModule,
  MenuModule,
  MessageModule,
  MultiSelectModule,
  OrderListModule,
  PopoverModule,
  PanelModule,
  PickListModule,
  ProgressSpinnerModule,
  RadioButtonModule,
  ScrollPanelModule,
  SelectButtonModule,
  DrawerModule,
  SplitButtonModule,
  InputNumberModule,
  StepsModule,
  TableModule,
  TabsModule,
  TieredMenuModule,
  ToastModule,
  ToolbarModule,
  TooltipModule,
  ToggleButtonModule,
  TreeModule,
  TreeTableModule,
  ListboxModule,
  BadgeModule,
  ConfirmPopupModule,
  SliderModule,
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
