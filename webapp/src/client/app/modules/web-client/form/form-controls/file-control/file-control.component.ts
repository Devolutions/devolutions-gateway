import {
    Component,
    ElementRef,
    Input,
    OnDestroy,
    OnInit,
    ViewChild,
} from '@angular/core';
import { SshKeyService } from '@gateway/shared/services/ssh-key.service';
import { ValidateFileResult } from '../../../../../shared/services/ssh-key.service';
import { WebFormService } from '@gateway/shared/services/web-form.service';

@Component({
    selector: 'app-file-control',
    templateUrl: './file-control.component.html',
    styleUrls: ['./file-control.component.scss'],
})
export class FileControlComponent implements OnInit, OnDestroy {
    @Input() isEnabled: boolean = true;
    @ViewChild('publicKeyFileControl') publicKeyFileControl: ElementRef;

    private uploadedFile: File = null;
    private fileValidateResult: ValidateFileResult = null;

    privateKeyContent: string = '';

    constructor(
        private sshKeyService: SshKeyService,
        private formService: WebFormService
    ) {
        this.uploadedFile = sshKeyService.getKeyFile();
        this.privateKeyContent = sshKeyService.getKeyContent();
    }

    ngOnDestroy(): void {
        this.formService.resetCanConnectCallback();
    }

    ngOnInit(): void {
        this.formService.canConnectIfAlsoTrue(() => {
            return this.sshKeyService.hasValidPrivateKey();
        });
    }

    clearPublicKeyData() {
        this.privateKeyContent = '';
        this.sshKeyService.removeFile();
        this.uploadedFile = null;
    }

    openFileSelector() {
        this.publicKeyFileControl.nativeElement.click();
    }

    onKeyFileSelection(event: InputEvent) {
        if ((event.target as HTMLInputElement).files.length !== 1) {
            return;
        }

        this.handleFiles((event.target as HTMLInputElement).files);
    }

    handleFiles(fileList: FileList) {
        if (fileList.length !== 1) {
            return;
        }

        this.uploadedFile = fileList[0];

        this.sshKeyService.validateFile(this.uploadedFile).subscribe((res) => {
            this.fileValidateResult = res;
            this.privateKeyContent = this.fileValidateResult.content || '';
            if (this.fileValidateResult.valid) {
                this.sshKeyService.saveFile(
                    this.uploadedFile,
                    this.fileValidateResult.content
                );
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
