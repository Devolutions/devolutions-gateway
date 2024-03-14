import { Component } from '@angular/core';
import { NetScanEntry, NetScanService } from '@gateway/shared/services/net-scan.services';

@Component({
  selector: 'app-net-scan',
  templateUrl: './net-scan.component.html',
  styleUrls: ['./net-scan.component.scss']
})
export class NetScanComponent {
  services: NetScanEntry[] = [];
  started: boolean = false;
  ended: boolean = false;

  constructor(private netscanService: NetScanService) {}

  startScan(): void {
    this.netscanService.startScan().subscribe({
      next: (entry: NetScanEntry) => {
        this.services.push(entry);
      },
      error: (e) => {
        this.ended = true;
      },
      complete: () => {
        this.ended = true;
      },
    });

    this.started = true;
  }

  onServiceClick(entry: NetScanEntry): void {
    this.netscanService.serviceSelected(entry);
  }
}
