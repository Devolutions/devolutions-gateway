import { Injectable } from '@angular/core';
import { Observable, BehaviorSubject, of } from 'rxjs';
import { WebFormService } from './web-form.service';

@Injectable({
  providedIn: 'root',
})
export class SshKeyService {
  private reader = new FileReader();
  private fileReadSubject = new BehaviorSubject<{
    format: SshKeyFormat;
    content: string;
  }>(null);
  private fileContent = null;
  private file: File;

  constructor(private webFormService: WebFormService) {
    console.log('SshKeyService created');
    this.reader.onload = () => {
      this.fileContent = this.reader.result as string;
      const keyFormat = recognizeKeyFormat(this.fileContent);
      this.fileReadSubject.next(keyFormat);
    };
  }

  saveFile(file: File, content: string) {
    this.file = file;
    this.webFormService.setExtraSessionParameter({ sshPrivateKey: content });
  }

  removeFile() {
    this.file = null;
    this.webFormService.setExtraSessionParameter({});
  }

  hasValidPrivateKey(): boolean {
    let value = this.fileReadSubject.getValue();
    return value !== null && value.format !== SshKeyFormat.PKCS8_Encrypted;
  }

  public validateFile(file: File | null): Observable<ValidateFileResult> {
    if (file === null) {
      return of({ valid: false, error: 'No file selected' });
    }

    this.reader.readAsText(file);

    return new Observable((observer) => {
      this.fileReadSubject.subscribe((value) => {
        if (value === null) {
          return {
            valid: false,
            error: 'Invalid key format',
          };
        }
        if (value.format === SshKeyFormat.Unknown) {
          observer.next({ valid: false, error: 'Invalid key format' });
        } else if (value.format == SshKeyFormat.PKCS8_Encrypted) {
          observer.next({ valid: false, error: 'Encrypted key not supported' });
        } else {
          observer.next({ valid: true, content: value.content });
        }
      });
    });
  }

  getKeyFile(): File {
    console.log('getKeyFile', this.file);
    return this.file;
  }
}

function recognizeKeyFormat(keyString): RecognizeKeyFormatResult {
  let format;
  if (
    keyString.includes('-----BEGIN RSA PRIVATE KEY-----') ||
    keyString.includes('-----BEGIN EC PRIVATE KEY-----')
  ) {
    format = SshKeyFormat.PEM;
  } else if (keyString.includes('-----BEGIN PRIVATE KEY-----')) {
    format = SshKeyFormat.PKCS8_Unencrypted;
  } else if (keyString.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----')) {
    format = SshKeyFormat.PKCS8_Encrypted;
  } else if (keyString.includes('-----BEGIN OPENSSH PRIVATE KEY-----')) {
    format = SshKeyFormat.OpenSSH;
  } else {
    format = SshKeyFormat.Unknown;
  }

  return { format, content: keyString };
}

export enum SshKeyFormat {
  PEM,
  PKCS8_Unencrypted,
  PKCS8_Encrypted,
  OpenSSH,
  Unknown,
}

export type ValidateFileResult =
  | {
      valid: true;
      content: string;
    }
  | {
      valid: false;
      error: string;
    };

export type RecognizeKeyFormatResult = {
  format: SshKeyFormat;
  content: string;
};
