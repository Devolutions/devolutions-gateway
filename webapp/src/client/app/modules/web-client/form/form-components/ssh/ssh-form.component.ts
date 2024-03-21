import {Component, Input, OnInit} from '@angular/core';
import {FormGroup} from "@angular/forms";

import {BaseComponent} from "@shared/bases/base.component";

@Component({
  selector: 'ssh-form',
  templateUrl: 'ssh-form.component.html',
  styleUrls: ['ssh-form.component.scss']
})
export class SshFormComponent extends BaseComponent implements  OnInit {

  @Input() form: FormGroup;
  @Input() inputFormData: any;

  constructor() {
    super();
  }

  ngOnInit(): void {
  }

}
