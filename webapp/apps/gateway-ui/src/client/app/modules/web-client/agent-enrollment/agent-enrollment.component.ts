import { Component, OnInit } from '@angular/core';
import { AgentEnrollmentStringResponse, AgentInfo } from '@shared/interfaces/agent.interfaces';
import { ApiService } from '@shared/services/api.service';
import { BaseComponent } from '@shared/bases/base.component';
import { takeUntil } from 'rxjs/operators';

@Component({
  standalone: false,
  selector: 'app-agent-enrollment',
  templateUrl: './agent-enrollment.component.html',
  styleUrls: ['./agent-enrollment.component.scss'],
})
export class AgentEnrollmentComponent extends BaseComponent implements OnInit {
  agents: AgentInfo[] = [];
  loading = false;

  // Enrollment form
  apiBaseUrl: string = window.location.origin;
  quicHost: string = window.location.hostname;
  agentName = '';
  tokenLifetime = 3600;

  // Generated enrollment data
  enrollmentResult: AgentEnrollmentStringResponse | null = null;
  generating = false;

  // Delete confirmation
  agentToDelete: AgentInfo | null = null;

  constructor(private apiService: ApiService) {
    super();
  }

  ngOnInit(): void {
    this.loadAgents();
  }

  loadAgents(): void {
    this.loading = true;
    this.apiService
      .listAgents()
      .pipe(takeUntil(this.destroyed$))
      .subscribe({
        next: (agents) => {
          this.agents = agents;
          this.loading = false;
        },
        error: (err) => {
          console.error('Failed to load agents', err);
          this.loading = false;
        },
      });
  }

  generateEnrollmentString(): void {
    this.generating = true;
    this.enrollmentResult = null;

    this.apiService
      .generateAgentEnrollmentString({
        api_base_url: this.apiBaseUrl,
        quic_host: this.quicHost || undefined,
        name: this.agentName || undefined,
        lifetime: this.tokenLifetime,
      })
      .pipe(takeUntil(this.destroyed$))
      .subscribe({
        next: (result) => {
          this.enrollmentResult = result;
          this.generating = false;
        },
        error: (err) => {
          console.error('Failed to generate enrollment string', err);
          this.generating = false;
        },
      });
  }

  confirmDelete(agent: AgentInfo): void {
    this.agentToDelete = agent;
  }

  cancelDelete(): void {
    this.agentToDelete = null;
  }

  deleteAgent(): void {
    if (!this.agentToDelete) return;
    const agentId = this.agentToDelete.agent_id;
    this.agentToDelete = null;

    this.apiService
      .deleteAgent(agentId)
      .pipe(takeUntil(this.destroyed$))
      .subscribe({
        next: () => {
          this.agents = this.agents.filter((a) => a.agent_id !== agentId);
        },
        error: (err) => {
          console.error('Failed to delete agent', err);
        },
      });
  }

  copyToClipboard(text: string): void {
    navigator.clipboard.writeText(text).catch((err) => {
      console.error('Failed to copy to clipboard', err);
    });
  }

  humanizeLastSeen(lastSeenMs: number): string {
    if (!lastSeenMs) return 'Never';
    const now = Date.now();
    const diffMs = now - lastSeenMs;

    if (diffMs < 0) return 'Just now';
    if (diffMs < 60_000) return `${Math.floor(diffMs / 1000)}s ago`;
    if (diffMs < 3_600_000) return `${Math.floor(diffMs / 60_000)}m ago`;
    if (diffMs < 86_400_000) return `${Math.floor(diffMs / 3_600_000)}h ago`;
    return `${Math.floor(diffMs / 86_400_000)}d ago`;
  }
}
