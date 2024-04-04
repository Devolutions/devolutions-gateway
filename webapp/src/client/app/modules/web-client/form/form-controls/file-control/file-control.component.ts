import { Component, Input, OnDestroy, OnInit, ViewChild } from '@angular/core';
import { SshKeyService } from '@gateway/shared/services/ssh-key.service';
import { ValidateFileResult } from '../../../../../shared/services/ssh-key.service';
import { WebFormService } from '@gateway/shared/services/web-form.service';
import { WebSessionService } from '@gateway/shared/services/web-session.service';

@Component({
  selector: 'app-file-control',
  templateUrl: './file-control.component.html',
  styleUrls: ['./file-control.component.scss'],
})
export class FileControlComponent implements OnInit, OnDestroy {
  @Input() isEnabled: boolean = true;

  uploadedFile: File = null;
  private fileValidateResult: ValidateFileResult = null;
  isHightlight: boolean = false;

  constructor(
    private sshKeyService: SshKeyService,
    private formService: WebFormService,
  ) {
    this.uploadedFile = sshKeyService.getKeyFile();
  }

  ngOnDestroy(): void {
    this.formService.resetCanConnectCallback();
  }

  ngOnInit(): void {
    this.formService.canConnectIfAlsoTrue(() => {
      return this.sshKeyService.hasValidPrivateKey();
    });
  }

  preventDefaults(event: DragEvent) {
    event.preventDefault();
    event.stopPropagation();
  }

  highlight(event: DragEvent) {
    this.preventDefaults(event);
    this.isHightlight = true;
  }

  unhighlight(event: DragEvent) {
    this.preventDefaults(event);
    this.isHightlight = false;
  }

  handleDrop(event: DragEvent) {
    this.preventDefaults(event);
    let files = event.dataTransfer?.files;
    if (files) {
      this.handleFiles(files);
    }
  }

  handleFiles(fileList: FileList) {
    if (fileList.length !== 1) {
      return;
    }

    this.uploadedFile = fileList[0];
    this.sshKeyService.validateFile(this.uploadedFile).subscribe((res) => {
      this.fileValidateResult = res;
      if (this.fileValidateResult.valid) {
        this.sshKeyService.saveFile(this.uploadedFile, this.fileValidateResult.content);
      }
    });
  }

  isValidFile(): boolean {
    return this.fileValidateResult ? this.fileValidateResult.valid : false;
  }

  removeFile() {
    this.uploadedFile = null;
    this.fileValidateResult = null;
    this.sshKeyService.removeFile();
  }

  getErrorMessage(): String {
    if (!this.fileValidateResult) {
      return '';
    }
    if (this.fileValidateResult.valid === false) {
      return this.fileValidateResult.error;
    }
    return '';
  }

  getFileSize(): string {
    if (!this.uploadedFile) {
      return '';
    }
    return `${this.uploadedFile.size} bytes`;
  }
}
