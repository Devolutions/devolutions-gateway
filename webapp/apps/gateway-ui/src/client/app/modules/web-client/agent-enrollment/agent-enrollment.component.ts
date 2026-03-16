import { Component } from '@angular/core';
import {
  AgentEnrollmentStringResponse,
  ApiService,
} from '@shared/services/api.service';

@Component({
  standalone: false,
  selector: 'app-agent-enrollment',
  templateUrl: './agent-enrollment.component.html',
  styleUrls: ['./agent-enrollment.component.scss'],
})
export class AgentEnrollmentComponent {
  requestedName = '';
  wireguardHost = window.location.hostname;
  lifetimeSeconds = 3600;
  isSubmitting = false;
  enrollment: AgentEnrollmentStringResponse | null = null;
  errorMessage = '';

  constructor(private readonly apiService: ApiService) {}

  submit(): void {
    this.isSubmitting = true;
    this.errorMessage = '';

    this.apiService
      .generateAgentEnrollmentString({
        name: this.requestedName || undefined,
        apiBaseUrl: window.location.origin,
        wireguardHost: this.wireguardHost || undefined,
        lifetime: this.lifetimeSeconds,
      })
      .subscribe({
        next: (result) => {
          this.enrollment = result;
          this.isSubmitting = false;
        },
        error: () => {
          this.errorMessage = 'Failed to generate the enrollment string.';
          this.isSubmitting = false;
        },
      });
  }

  async copy(value: string): Promise<void> {
    await navigator.clipboard.writeText(value);
  }
}
