import { Injectable, isDevMode } from '@angular/core';
import { Protocol } from '../enums/web-client-protocol.enum';
import { ApiService } from './api.service';
import { environment } from 'src/environments/environment';
import { v4 as uuidv4 } from 'uuid';
import { from } from 'rxjs';

@Injectable({
  providedIn: 'root',
})
export class AnalyticService {
  private openedConnections: Map<
    string,
    {
      startTime: Date;
      sessionType: ProtocolString;
    }
  > = new Map();

  constructor(private apiService: ApiService) {
    window.addEventListener('beforeunload', () => {
      this.sendCloseAllEvents();
    });
  }

  public sendOpenEvent(connectionType: ProtocolString): ConnectionIdentifier {
    this.sendEvent({
      connectionType: connectionType,
    });

    let connectionId = uuidv4();
    this.openedConnections.set(connectionId, {
      startTime: new Date(),
      sessionType: connectionType,
    });

    return {
      id: connectionId,
      type: connectionType,
    };
  }

  public sendCloseEvent(connectionId: ConnectionIdentifier): void {
    let connection = this.openedConnections.get(connectionId.id);
    if (!connection) {
      return;
    }
    this.openedConnections.delete(connectionId.id);
    let duration = new Date().getTime() - connection.startTime.getTime();
    let durationInSeconds = duration / 1000;

    this.sendEvent({
      connectionType: connection.sessionType,
      duration: durationInSeconds,
    });
  }

  sendCloseAllEvents(): void {
    this.openedConnections.forEach((connection, id) => {
      this.openedConnections.delete(id);
      let duration = new Date().getTime() - connection.startTime.getTime();
      let durationInSeconds = duration / 1000;

      this.sendEvent({
        connectionType: connection.sessionType,
        duration: durationInSeconds,
      });
    });
  }

  private sendEvent(
    connectinoEvent: OpenedConnectionEvent | ClosedConnectionEvent
  ): void {
    let host = environment.OpenSearchUrl;
    let user = environment.OpenSearchUser;
    let password = environment.OpenSearchPassword;
    let indexName = environment.OpenSearchIndex;

    let installId = localStorage.getItem('installId');
    if (!installId) {
      installId = uuidv4();
      localStorage.setItem('installId', installId);
    }

    this.apiService.getVersion().subscribe((version) => {
      let event: AnalyticEvent = {
        application: {
          version: version.version,
        },
        eventDate: new Date().toISOString(),
        userAgent: navigator.userAgent,
        installID: installId,
        ...connectinoEvent,
      };

      const headers = new Headers();
      headers.append('Content-Type', 'application/json');
      headers.append('Authorization', `Basic ${btoa(user + ':' + password)}`);

      let url = `${host}${indexName}/_doc`;
      const requestOptions: RequestInit = {
        method: 'POST',
        headers: headers,
        body: JSON.stringify(event),
        // mode: 'no-cors'  // Add this line to set the mode to 'no-cors'
      };

      fetch(url, requestOptions)
        .then((response) => {
          if (isDevMode()) {
            console.log('Event sent', response);
          }
        })
        .catch((error) => {
          if (isDevMode()) {
            console.error('Error sending event', error);
          }
        });
    });
  }
}

export interface ConnectionIdentifier {
  id: string;
  type: ProtocolString;
}

export interface AnalyticEventBasic {
  application: {
    version: string;
  };
  eventDate: string;
  userAgent: string;
  installID: string;
}
export type ProtocolString = keyof typeof Protocol;
interface OpenedConnectionEvent {
  connectionType: ProtocolString;
}

interface ClosedConnectionEvent {
  connectionType: ProtocolString;
  duration: number;
}

export type AnalyticEvent = AnalyticEventBasic &
  (OpenedConnectionEvent | ClosedConnectionEvent);
