import { Component, AfterViewInit } from '@angular/core';
import { NetScanEntry, NetScanService } from '@gateway/shared/services/net-scan.services';

@Component({
  selector: 'app-net-scan',
  templateUrl: './net-scan.component.html',
  styleUrls: ['./net-scan.component.scss']
})
export class NetScanComponent implements AfterViewInit {
  services: NetScanEntry[] = [];
  started: boolean = false;
  ended: boolean = false;

  constructor(private netscanService: NetScanService) {}

  ngAfterViewInit(): void {
    this.startScan();
  }

  startScan(): void {
    this.started = true;
    this.ended = false;
    this.services = [];
    this.netscanService.startScan().subscribe({
      next: (entry: NetScanEntry) => {
        this.services.push(entry);
      },
      error: () => {
        this.ended = true;
      },
      complete: () => {
        this.ended = true;
      },
    });
  }

  onServiceClick(entry: NetScanEntry): void {
    this.netscanService.serviceSelected(entry);
  }
}
