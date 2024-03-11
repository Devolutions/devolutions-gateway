import { Component } from '@angular/core';
import { NetScanEntry } from '@gateway/shared/services/net-scan.services';

@Component({
  selector: 'app-net-scan',
  templateUrl: './net-scan.component.html',
  styleUrls: ['./net-scan.component.scss']
})
export class NetScanComponent {
  services: NetScanEntry[] = [];

  serivice =  {
      ip: '123.123.123.123',
      hostname: 'www.example.com',
      protocol: 'HTTPS'
  }

  constructor() {
    let handle = setInterval(() => {
      // this.services.push(this.serivice);
    }, 1000);

    setTimeout(() => {
      clearInterval(handle);
    }, 5000);
  }
}
