import { Injectable } from '@angular/core';
import { WebSessionService } from './web-session.service';
import { Observable, BehaviorSubject, of } from 'rxjs';
import { take, tap } from 'rxjs/operators';

@Injectable({
  providedIn: 'root',
})
export class SshKeyService {
  private reader = new FileReader();
  private fileReadSubject = new BehaviorSubject<SshKeyFormat>(null);
  private fileContent = null;
  private file: File;

  constructor(private webSessionService: WebSessionService) {
    console.log('SshKeyService created');
    this.reader.onload = () => {
      this.fileContent = this.reader.result as string;
      const keyFormat = recognizeKeyFormat(this.fileContent);
      this.fileReadSubject.next(keyFormat);
    };
  }

  addLastValidatedKeyToWebSession() {
    if (!this.hasValidPrivateKey()) {
      throw new Error('Invalid private key');
    }
    this.webSessionService.addExtraSessionData({
      sshPrivateKey: this.fileContent,
    });
  }

  hasValidPrivateKey(): boolean {
    let value = this.fileReadSubject.getValue();
    return value !== null && value !== SshKeyFormat.PKCS8_Encrypted;
  }

  public validateFile(
    file: File | null
  ): Observable<{ valid: boolean; error: String }> {
    if (file === null) {
      return of({ valid: false, error: 'No file selected' });
    }

    this.reader.readAsText(file);

    return new Observable((observer) => {
      this.fileReadSubject.subscribe((keyFormat) => {
        if (keyFormat === null) {
          return;
        }
        if (keyFormat === SshKeyFormat.Unknown) {
          observer.next({ valid: false, error: 'Invalid key format' });
        } else if (keyFormat == SshKeyFormat.PKCS8_Encrypted) {
          observer.next({ valid: false, error: 'Encrypted key not supported' });
        } else {
          observer.next({ valid: true, error: null });
        }
      });
    }).pipe(tap(() => (this.file = file))) as Observable<{
      valid: boolean;
      error: String;
    }>;
  }

  getKeyFile(): File {
    console.log('getKeyFile', this.file)
    return this.file;
  }
}

function recognizeKeyFormat(keyString): SshKeyFormat {
  if (
    keyString.includes('-----BEGIN RSA PRIVATE KEY-----') ||
    keyString.includes('-----BEGIN EC PRIVATE KEY-----')
  ) {
    return SshKeyFormat.PEM;
  } else if (keyString.includes('-----BEGIN PRIVATE KEY-----')) {
    return SshKeyFormat.PKCS8_Unencrypted;
  } else if (keyString.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----')) {
    return SshKeyFormat.PKCS8_Encrypted;
  } else if (keyString.includes('-----BEGIN OPENSSH PRIVATE KEY-----')) {
    return SshKeyFormat.OpenSSH;
  } else {
    return SshKeyFormat.Unknown;
  }
}

export enum SshKeyFormat {
  PEM,
  PKCS8_Unencrypted,
  PKCS8_Encrypted,
  OpenSSH,
  Unknown,
}
