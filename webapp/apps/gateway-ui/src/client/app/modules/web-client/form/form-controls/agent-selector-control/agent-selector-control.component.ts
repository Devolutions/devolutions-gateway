import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';
import { AgentInfo } from '@shared/interfaces/agent.interfaces';
import { ApiService } from '@shared/services/api.service';
import { BaseComponent } from '@shared/bases/base.component';
import { WebFormService } from '@shared/services/web-form.service';
import { takeUntil } from 'rxjs/operators';

@Component({
  standalone: false,
  selector: 'web-client-agent-selector-control',
  templateUrl: './agent-selector-control.component.html',
  styleUrls: ['./agent-selector-control.component.scss'],
})
export class AgentSelectorControlComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;

  agents: AgentInfo[] = [];
  hasAgents = false;

  constructor(
    private apiService: ApiService,
    private formService: WebFormService,
  ) {
    super();
  }

  ngOnInit(): void {
    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: 'agentId',
      inputFormData: this.inputFormData,
      isRequired: false,
      defaultValue: null,
    });

    this.apiService
      .listAgents()
      .pipe(takeUntil(this.destroyed$))
      .subscribe({
        next: (agents) => {
          this.agents = agents.filter((a) => a.is_online);
          this.hasAgents = this.agents.length > 0;
        },
        error: () => {
          this.agents = [];
          this.hasAgents = false;
        },
      });
  }

  getAgentLabel(agent: AgentInfo): string {
    const subnets = agent.subnets.length > 0 ? ` (${agent.subnets.join(', ')})` : '';
    return `${agent.name}${subnets}`;
  }
}
