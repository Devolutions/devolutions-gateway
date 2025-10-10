import { AfterViewInit, ChangeDetectorRef, Component } from '@angular/core';
import { NetScanEntry, NetScanService } from '@gateway/shared/services/net-scan.services';

@Component({
  selector: 'app-net-scan',
  templateUrl: './net-scan.component.html',
  styleUrls: ['./net-scan.component.scss'],
})
export class NetScanComponent implements AfterViewInit {
  services: NetScanEntry[] = [];
  started = false;
  ended = false;

  constructor(
    private netscanService: NetScanService,
    private cd: ChangeDetectorRef,
  ) {}

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
      error: (_e) => {
        this.ended = true;
      },
      complete: () => {
        this.ended = true;
      },
    });
  }

  forceScan(): void {
    this.netscanService.newScan();
    this.startScan();
  }

  onServiceClick(entry: NetScanEntry): void {
    this.netscanService.serviceSelected(entry);
  }

  serviceTitle(service: NetScanEntry): string {
    return service.hostname ? service.hostname : service.ip;
  }

  serviceSubtitle(service: NetScanEntry): string {
    return service.hostname ? service.ip : ' ';
  }
}
