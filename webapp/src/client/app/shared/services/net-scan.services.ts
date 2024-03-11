import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of } from 'rxjs';

export type NetScanEntry = {
    ip:string,
    hostname:string,
    protocol:string
}


@Injectable({
    providedIn: 'root'
})
export class NetScanService {
  constructor(private http: HttpClient) {}

  public startScan() : Observable<NetScanEntry> {
    //TODO: Implement this method
    return of()
  }
}
