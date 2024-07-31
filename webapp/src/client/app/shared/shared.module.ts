import {ModuleWithProviders, NgModule} from '@angular/core';
import {CommonModule} from '@angular/common';
import {RouterModule} from '@angular/router';
import {ReactiveFormsModule} from '@angular/forms';
import {PrimeNgModules} from "@shared/primeng.module";
import {TooltipEllipsisDirective} from "@shared/directives/tooltip-ellipsis.directive";
import {Tooltip} from "primeng/tooltip";

@NgModule({
    imports: [
        CommonModule,
        ReactiveFormsModule,
        RouterModule,
        PrimeNgModules,
    ],
  declarations: [
    TooltipEllipsisDirective
  ],
  exports: [
    CommonModule,
    ReactiveFormsModule,
    RouterModule,
    PrimeNgModules,
    TooltipEllipsisDirective
  ],
  providers: [Tooltip],
})

export class SharedModule {
  static forRoot(): ModuleWithProviders<SharedModule> {
    return {
      ngModule: SharedModule,
      providers: [Tooltip],
    };
  }
}
