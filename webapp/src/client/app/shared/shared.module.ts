import { CommonModule } from '@angular/common';
import { ModuleWithProviders, NgModule } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { TooltipEllipsisDirective } from '@shared/directives/tooltip-ellipsis.directive';
import { PrimeNgModules } from '@shared/primeng.module';
import { Tooltip } from 'primeng/tooltip';

@NgModule({
  imports: [CommonModule, ReactiveFormsModule, RouterModule, PrimeNgModules],
  declarations: [TooltipEllipsisDirective],
  exports: [CommonModule, ReactiveFormsModule, RouterModule, PrimeNgModules, TooltipEllipsisDirective],
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
