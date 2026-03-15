import { Component, Input, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';
import { DropdownChangeEvent } from 'primeng/dropdown';

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
  @Input() destination: string; // Target destination to auto-select agent

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

        // Auto-select agent if destination is provided
        if (this.destination && this.agents.length > 0) {
          this.autoSelectAgent();
        }
      },
      error: (error) => {
        console.error('Failed to load agents', error);
        this.loading = false;
        this.showAgentSelector = false;
      },
    });
  }

  private autoSelectAgent(): void {
    this.apiService.resolveTarget(this.destination).subscribe({
      next: (response) => {
        if (response.reachable_agents.length > 0) {
          // Select the first reachable agent
          const selectedAgent = response.reachable_agents[0];
          this.parentForm.get('agentId')?.setValue(selectedAgent.agent_id);
        }
      },
      error: (error) => {
        console.error('Failed to resolve target', error);
      },
    });
  }

  onAgentChange(event: DropdownChangeEvent): void {
    const agentId = event.value;
    this.parentForm.get('agentId')?.setValue(agentId);
  }

  getAgentLabel(agent: AgentInfo): string {
    return `${agent.name} (${agent.assigned_ip}) - ${agent.advertised_subnets.join(', ')}`;
  }
}
