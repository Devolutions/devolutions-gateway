import { Injectable } from '@angular/core';
import { ProtocolIconMap, ProtocolNameToProtocolMap } from '@gateway/app.constants';
import { from, merge, Observable, Subject } from 'rxjs';
import { map } from 'rxjs/operators';
import { Protocol } from '../enums/web-client-protocol.enum';
import { WebClientService } from './web-client.service';

export type NetScanEntry = {
  ip: string;
  hostname: string;
  protocol: Protocol;
  icon: () => string;
};

@Injectable({
  providedIn: 'root',
})
export class NetScanService {
  private scanUrl = '/jet/net/scan';
  private serviceUpdatePipe: Subject<NetScanEntry> = new Subject<NetScanEntry>();

  // JS set doesn't allow customized equality check, so we stringify for deep comparison
  private serviceCache: Set<string> = new Set<string>();
  private scanSubject = new Subject<NetScanEntry>();

  constructor(private webClientService: WebClientService) {
    this.newScan();
  }

  public newScan() {
    this.serviceCache.clear();
    // Reset the subject, Subject will not emit any new value after complete or error
    this.scanSubject = new Subject<NetScanEntry>();
    this.webClientService
      .fetchNetScanToken()
      .pipe(
        map((token: string) => {
          const path = `${this.scanUrl}?token=${token}`;
          const url_http = new URL(path, window.location.href).toString();
          const url = url_http.replace('http', 'ws');
          return new WebSocket(url);
        }),
      )
      .subscribe({
        next: (socket: WebSocket) => {
          socket.onmessage = (event) => {
            this.socketOnMessage(event);
          };
          socket.onclose = () => {
            this.scanSubject.complete();
          };
          socket.onerror = (e) => {
            console.error('Error scanning network');
            this.scanSubject.error(e);
          };
        },

        error: (error) => {
          // Error create the websocket
          this.scanSubject.error(error);
        },
      });
  }

  public startScan(): Observable<NetScanEntry> {
    const existingObservable = from(this.serviceCache).pipe(
      map((entry: string) => {
        const toAdd = JSON.parse(entry);
        toAdd.icon = () => {
          return ProtocolIconMap[toAdd.protocol];
        };
        return toAdd;
      }),
    );

    return merge(existingObservable, this.scanSubject.asObservable());
  }

  serviceSelected(entry: NetScanEntry) {
    this.serviceUpdatePipe.next(entry);
  }

  onServiceSelected(): Observable<NetScanEntry> {
    return this.serviceUpdatePipe.asObservable();
  }

  socketOnMessage(event) {
    const entry: {
      ip: string;
      hostname: string;
      protocol: string;
    } = JSON.parse(event.data);

    const protocol = ProtocolNameToProtocolMap[entry.protocol];
    // We don't yet support this protocol
    if (!protocol) {
      return;
    }

    const value = {
      ip: entry.ip,
      hostname: entry.hostname,
      protocol: protocol,
    };

    if (this.serviceCache.has(JSON.stringify(value))) {
      return;
    }
    this.serviceCache.add(JSON.stringify(value));
    this.scanSubject.next({
      ...value,
      icon: () => {
        return ProtocolIconMap[protocol];
      },
    });
  }
}
