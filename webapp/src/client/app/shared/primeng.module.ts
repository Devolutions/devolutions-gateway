import {NgModule} from '@angular/core';

import {TableModule} from 'primeng/table';
import {DataViewModule} from 'primeng/dataview';
import {VirtualScrollerModule} from 'primeng/virtualscroller';
import {DeferModule} from 'primeng/defer';
import {AutoCompleteModule} from 'primeng/autocomplete';
import {AccordionModule} from 'primeng/accordion';
import {ButtonModule} from 'primeng/button';
import {CalendarModule} from 'primeng/calendar';
import {CardModule} from 'primeng/card';
import {CarouselModule} from 'primeng/carousel';
import {CheckboxModule} from 'primeng/checkbox';
import {ChipsModule} from 'primeng/chips';
import {ContextMenuModule} from 'primeng/contextmenu';
import {Dialog, DialogModule} from 'primeng/dialog';
import {DropdownModule} from 'primeng/dropdown';
import {FieldsetModule} from 'primeng/fieldset';
import {ConfirmDialogModule} from 'primeng/confirmdialog';
import {FileUploadModule} from 'primeng/fileupload';
import {InputMaskModule} from 'primeng/inputmask';
import {InputSwitchModule} from 'primeng/inputswitch';
import {ListboxModule} from 'primeng/listbox';
import {MenuModule} from 'primeng/menu';
import {MessageModule} from 'primeng/message';
import {MultiSelectModule} from 'primeng/multiselect';
import {OverlayPanelModule} from 'primeng/overlaypanel';
import {OrderListModule} from 'primeng/orderlist';
import {PickListModule} from 'primeng/picklist';
import {ProgressSpinnerModule} from 'primeng/progressspinner';
import {RadioButtonModule} from 'primeng/radiobutton';
import {ScrollPanelModule} from 'primeng/scrollpanel';
import {SelectButtonModule} from 'primeng/selectbutton';
import {SidebarModule} from 'primeng/sidebar';
import {StepsModule} from 'primeng/steps';
import {TabMenuModule} from 'primeng/tabmenu';
import {TabViewModule} from 'primeng/tabview';
import {TieredMenuModule} from 'primeng/tieredmenu';
import {TriStateCheckboxModule} from 'primeng/tristatecheckbox';
import {ToolbarModule} from 'primeng/toolbar';
import {Tooltip, TooltipModule} from 'primeng/tooltip';
import {ToggleButtonModule} from 'primeng/togglebutton';
import {TreeModule} from 'primeng/tree';
import {TreeTableModule} from 'primeng/treetable';
import {MessagesModule} from 'primeng/messages';
import {PanelModule} from 'primeng/panel';
import {ConfirmationService, MessageService} from 'primeng/api';
import {SplitButtonModule} from 'primeng/splitbutton';
import {DomHandler} from 'primeng/dom';
import {ToastModule} from 'primeng/toast';
import {BadgeModule} from 'primeng/badge';
import {InputNumberModule} from 'primeng/inputnumber';
import {ConfirmPopupModule} from 'primeng/confirmpopup';
import {DividerModule} from 'primeng/divider';
import {InputTextareaModule} from 'primeng/inputtextarea';
import {InputTextModule} from 'primeng/inputtext';

const PRIMENG_MODULES = [
    DividerModule,
    AccordionModule,
    AutoCompleteModule,
    ButtonModule,
    CalendarModule,
    CardModule,
    CarouselModule,
    CheckboxModule,
    ChipsModule,
    ContextMenuModule,
    DataViewModule,
    VirtualScrollerModule,
    DeferModule,
    DialogModule,
    DropdownModule,
    FieldsetModule,
    ConfirmDialogModule,
    FieldsetModule,
    FileUploadModule,
    InputMaskModule,
    InputSwitchModule,
    InputTextareaModule,
    InputTextModule,
    ListboxModule,
    MenuModule,
    MessagesModule,
    MessageModule,
    MultiSelectModule,
    OrderListModule,
    OverlayPanelModule,
    PanelModule,
    PickListModule,
    ProgressSpinnerModule,
    RadioButtonModule,
    ScrollPanelModule,
    SelectButtonModule,
    SidebarModule,
    SplitButtonModule,
    InputNumberModule,
    StepsModule,
    TableModule,
    TabMenuModule,
    TabViewModule,
    TieredMenuModule,
    TriStateCheckboxModule,
    ToastModule,
    ToolbarModule,
    TooltipModule,
    ToggleButtonModule,
    TreeModule,
    TreeTableModule,
    ListboxModule,
    BadgeModule,
    ConfirmPopupModule
];

@NgModule({
    imports: PRIMENG_MODULES,
    exports: PRIMENG_MODULES,
    providers: [ConfirmationService, MessageService]
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

                if ((!minWidth || newWidth > parseInt(minWidth, 10)) && (offset.left + newWidth) < viewport.width) {
                    this.container.style.width = newWidth + 'px';
                }

                if ((!minHeight || newHeight > parseInt(minHeight, 10)) && (offset.top + newHeight) < viewport.height) {
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
