import { Component, OnInit } from '@angular/core';
import {
  AgentEnrollmentStringResponse,
  ApiService,
} from '@shared/services/api.service';
import { AgentInfo } from '@shared/interfaces/agent.interfaces';
import { timer } from 'rxjs';

@Component({
  standalone: false,
  selector: 'app-agent-enrollment',
  templateUrl: './agent-enrollment.component.html',
  styleUrls: ['./agent-enrollment.component.scss'],
})
export class AgentEnrollmentComponent implements OnInit {
  // Agent list
  agents: AgentInfo[] = [];
  isLoadingAgents = true;
  agentsError = '';

  // Enrollment form
  requestedName = '';
  apiBaseUrl = window.location.origin;
  wireguardHost = window.location.hostname;
  lifetimeSeconds = 3600;
  isSubmitting = false;
  enrollment: AgentEnrollmentStringResponse | null = null;
  errorMessage = '';
  copiedField: 'command' | 'string' | null = null;

  constructor(private readonly apiService: ApiService) {}

  ngOnInit(): void {
    this.refreshAgents();
  }

  refreshAgents(): void {
    this.isLoadingAgents = true;
    this.agentsError = '';
    this.apiService.listAgents().subscribe({
      next: (response) => {
        this.agents = response.agents;
        this.isLoadingAgents = false;
      },
      error: (error: Error) => {
        this.agentsError = error.message || 'Failed to load agents.';
        this.isLoadingAgents = false;
      },
    });
  }

  deleteAgent(agent: AgentInfo): void {
    if (!confirm(`Delete agent "${agent.name}"? This cannot be undone.`)) {
      return;
    }
    this.apiService.deleteAgent(agent.agent_id).subscribe({
      next: () => this.refreshAgents(),
      error: (error: Error) => {
        this.agentsError = error.message || 'Failed to delete agent.';
      },
    });
  }

  formatLastSeen(unixTimestamp?: number): string {
    if (!unixTimestamp) return 'Never';
    const date = new Date(unixTimestamp * 1000);
    const now = Date.now();
    const diffMs = now - date.getTime();
    const diffSec = Math.floor(diffMs / 1000);
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return `${diffHr}h ago`;
    return date.toLocaleDateString();
  }

  submit(): void {
    this.isSubmitting = true;
    this.errorMessage = '';

    this.apiService
      .generateAgentEnrollmentString({
        name: this.requestedName || undefined,
        apiBaseUrl: this.apiBaseUrl,
        wireguardHost: this.wireguardHost || undefined,
        lifetime: this.lifetimeSeconds,
      })
      .subscribe({
        next: (result) => {
          this.enrollment = result;
          this.copiedField = null;
          this.isSubmitting = false;
          this.refreshAgents();
        },
        error: (error: Error) => {
          this.errorMessage = error.message || 'Failed to generate the enrollment string.';
          this.isSubmitting = false;
        },
      });
  }

  async copy(field: 'command' | 'string', value: string): Promise<void> {
    await navigator.clipboard.writeText(value);
    this.copiedField = field;
    timer(2000).subscribe(() => {
      if (this.copiedField === field) {
        this.copiedField = null;
      }
    });
  }

  get commandButtonLabel(): string {
    return this.copiedField === 'command' ? 'Copied' : 'Copy';
  }

  get stringButtonLabel(): string {
    return this.copiedField === 'string' ? 'Copied' : 'Copy';
  }
}
