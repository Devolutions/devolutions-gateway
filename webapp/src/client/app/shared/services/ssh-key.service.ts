import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, of } from 'rxjs';
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
    this.reader.onload = () => {
      this.fileContent = this.reader.result as string;
      const keyFormat = recognizeKeyFormat(this.fileContent);
      this.fileReadSubject.next(keyFormat);
    };
  }

  saveFile(file: File, content: string) {
    this.file = file;
    this.fileContent = content;
    this.webFormService.setExtraSessionParameter({ sshPrivateKey: this.fileContent });
  }

  getKeyContent(): string {
    return this.fileContent;
  }

  removeFile() {
    this.file = null;
    this.webFormService.setExtraSessionParameter({});
  }

  hasValidPrivateKey(): boolean {
    const value = this.fileReadSubject.getValue();
    return value !== null && value.format !== SshKeyFormat.PKCS8_Encrypted;
  }

  public validateFile(file: File | null): Observable<ValidateFileResult> {
    if (file === null) {
      return of({ valid: false, error: 'No file selected' });
    }

    if (file.size > 10000) {
      return of({ valid: false, error: 'File size is too large, must be less than 10kb' });
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
          observer.next({
            valid: false,
            error: 'Invalid key format',
            content: value.content,
          });
        } else {
          observer.next({ valid: true, content: value.content });
        }
      });
    });
  }

  getKeyFile(): File {
    return this.file;
  }
}

function recognizeKeyFormat(keyString): RecognizeKeyFormatResult {
  let format: SshKeyFormat;
  if (keyString.includes('-----BEGIN RSA PRIVATE KEY-----') || keyString.includes('-----BEGIN EC PRIVATE KEY-----')) {
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
  PEM = 0,
  PKCS8_Unencrypted = 1,
  PKCS8_Encrypted = 2,
  OpenSSH = 3,
  Unknown = 4,
}

export type ValidateFileResult =
  | {
      valid: true;
      content: string;
    }
  | {
      valid: false;
      error: string;
      content?: string;
    };

export type RecognizeKeyFormatResult = {
  format: SshKeyFormat;
  content: string;
};
