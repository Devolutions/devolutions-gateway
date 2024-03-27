import { Component, Input } from '@angular/core';
import { FileSelectEvent } from 'primeng/fileupload';

@Component({
  selector: 'app-file-control',
  templateUrl: './file-control.component.html',
  styleUrls: ['./file-control.component.scss']
})
export class FileControlComponent {
  @Input() isEnabled: boolean = true;

  uploadedFiles: File = null;

  onSelect(event: FileSelectEvent) {
    if (event.currentFiles.length !== 1) {
      return;
    }

    this.uploadedFiles = event.currentFiles[0];
  }
}
