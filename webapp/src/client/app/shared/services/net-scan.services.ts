import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, Subject, of } from 'rxjs';
import { Protocol } from '../enums/web-client-protocol.enum';
import {
  WebSessionService,
  ProtocolIconMap,
  ProtocolNameToProtocolMap
} from './web-session.service';
import { WebClientService } from './web-client.service';
import { map } from 'rxjs/operators';

export type NetScanEntry = {
  ip: string;
  hostname: string;
  protocol: Protocol;
  icon: () => string;
};

@Injectable({
  providedIn: 'root'
})
export class NetScanService {
  private scanUrl = '/jet/net/scan';
  private serviceUpdatePipe: Subject<NetScanEntry> = new Subject<NetScanEntry>();

  constructor(private webClientService: WebClientService) {}

  public startScan(): Observable<NetScanEntry> {
    return new Observable<NetScanEntry>((observer) => {
      this.webClientService
        .fetchNetScanToken()
        .pipe(
          map((token: string) => {
            let path = `${this.scanUrl}?token=${token}`;
            let url_http = new URL(path, window.location.href).toString();
            let url = url_http.replace('http', 'ws');
            return new WebSocket(url);
          })
        )
        .subscribe((socket: WebSocket) => {
          socket.onmessage = (event) => {
            let entry: {
              ip: string;
              hostname: string;
              protocol: string;
            } = JSON.parse(event.data);

            let protocol = ProtocolNameToProtocolMap[entry.protocol];
            // We don't yet support this protocol
            if (!protocol) {
              return;
            }
            let value = {
              ip: entry.ip,
              hostname: entry.hostname,
              protocol: protocol,
              icon: () => {
                return ProtocolIconMap[protocol];
              }
            };
            observer.next(value);
          };

          socket.onclose = () => {
            observer.complete();
          };
        });
    });
  }

  serviceSelected(entry: NetScanEntry) {
    this.serviceUpdatePipe.next(entry);
  }

  onServiceSelected(): Observable<NetScanEntry> {
    return this.serviceUpdatePipe.asObservable();
  }
}
