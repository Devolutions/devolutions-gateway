import { Component, Input } from '@angular/core';
import { SshKeyService } from '@gateway/shared/services/ssh-key.service';
import { FileSelectEvent } from 'primeng/fileupload';

export type FileValidateResult = { valid: boolean; error: String };

@Component({
  selector: 'app-file-control',
  templateUrl: './file-control.component.html',
  styleUrls: ['./file-control.component.scss'],
})
export class FileControlComponent {
  @Input() isEnabled: boolean = true;

  uploadedFile: File = null;
  private fileValidationResult: FileValidateResult = null;

  constructor(private sshKeyService: SshKeyService) {
    this.uploadedFile = sshKeyService.getKeyFile()
  }

  onSelect(event: FileSelectEvent) {
    if (event.currentFiles.length !== 1) {
      return;
    }
    this.uploadedFile = event.currentFiles[0];
    this.sshKeyService.validateFile(this.uploadedFile).subscribe((res) => {
      this.fileValidationResult = res;
      this.sshKeyService.addLastValidatedKeyToWebSession();
    });
  }

  isValidFile(): boolean {
    let res = this.fileValidationResult && this.fileValidationResult.valid;
    return res;
  }

  getErrorMessage(): String {
    return this.fileValidationResult ? this.fileValidationResult.error : null;
  }
}
