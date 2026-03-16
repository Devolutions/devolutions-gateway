import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';
import type { SelectChangeEvent } from 'primeng/select';

import { BaseComponent } from '@shared/bases/base.component';
import { WebFormService } from '@shared/services/web-form.service';
import { ApiService } from '@shared/services/api.service';
import type { AgentInfo } from '@shared/interfaces/agent.interfaces';

@Component({
  standalone: false,
  selector: 'web-client-agent-selector-control',
  templateUrl: 'agent-selector-control.component.html',
  styleUrls: ['agent-selector-control.component.scss'],
})
export class AgentSelectorControlComponent extends BaseComponent implements OnInit {
  @Input() parentForm: FormGroup;
  @Input() inputFormData;

  agents: AgentInfo[] = [];
  loading = false;
  showAgentSelector = false; // Only show if agents are available

  constructor(
    private formService: WebFormService,
    private apiService: ApiService,
  ) {
    super();
  }

  ngOnInit(): void {
    this.formService.addControlToForm({
      formGroup: this.parentForm,
      controlName: 'agentId',
      inputFormData: this.inputFormData,
    });

    this.loadAgents();
  }

  private loadAgents(): void {
    this.loading = true;
    this.apiService.listAgents().subscribe({
      next: (response) => {
        this.agents = response.agents.filter((agent) => agent.status === 'online');
        this.showAgentSelector = this.agents.length > 0;
        this.loading = false;
      },
      error: (error) => {
        console.error('Failed to load agents', error);
        this.loading = false;
        this.showAgentSelector = false;
      },
    });
  }

  onAgentChange(event: SelectChangeEvent): void {
    const agentId = event.value;
    this.parentForm.get('agentId')?.setValue(agentId);
  }

  getAgentLabel(agent: AgentInfo): string {
    return `${agent.name} (${agent.assigned_ip}) - ${agent.advertised_subnets.join(', ')}`;
  }
}
