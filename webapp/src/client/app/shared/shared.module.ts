import {ModuleWithProviders, NgModule} from '@angular/core';
import {CommonModule} from '@angular/common';
import {RouterModule} from '@angular/router';
import {ReactiveFormsModule} from '@angular/forms';
import {PrimeNgModules} from "@shared/primeng.module";

@NgModule({
    imports: [
        CommonModule,
        ReactiveFormsModule,
        RouterModule,
        PrimeNgModules
    ],
  declarations: [
  ],
  exports: [
    CommonModule,
    ReactiveFormsModule,
    RouterModule,
    PrimeNgModules
  ],
  providers: [ ],
})

export class SharedModule {
  static forRoot(): ModuleWithProviders<SharedModule> {
    return {
      ngModule: SharedModule,
      providers: [],
    };
  }
}
