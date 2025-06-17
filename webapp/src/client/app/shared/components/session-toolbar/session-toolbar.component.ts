import { Component, ElementRef, HostListener, Input } from '@angular/core';
import { UtilsService } from '@shared/services/utils.service';

@Component({
  selector: 'session-toolbar',
  templateUrl: 'session-toolbar.component.html',
  styleUrls: ['session-toolbar.component.scss'],
})
export class SessionToolbarComponent {
  @Input() sessionContainerParent: ElementRef;

  @Input() leftButtons: {
    label: string;
    icon: string;
    action: () => void;
  }[] = [];

  @Input() middleButtons: {
    label: string;
    icon: string;
    action: () => void;
  }[] = [];

  @Input() middleToggleButtons: {
    label: string;
    icon: string;
    action: () => void;
    isActive: () => boolean;
  }[] = [];

  @Input() rightButtons: {
    label: string;
    icon: string;
    action: () => void;
  }[] = [];

  @Input() checkboxes: {
    label: string;
    value: boolean;
    onChange: (value: boolean) => void;
    enabled: () => boolean;
  }[] = [];

  @Input() sliders: {
    label: string;
    value: number;
    onChange: (value: number) => void;
    min: number;
    max: number;
    step: number;
  }[] = [];

  isFullScreenMode = false;
  showToolbarDiv = true;
  loading = true;

  constructor(protected utils: UtilsService) {}

  @HostListener('document:mousemove', ['$event'])
  onMouseMove(event: MouseEvent): void {
    this.handleSessionToolbarDisplay(event);
  }

  @HostListener('document:fullscreenchange')
  onFullScreenChange(): void {
    this.isFullScreenMode = !!document.fullscreenElement;
  }

  private handleSessionToolbarDisplay(event: MouseEvent): void {
    if (!document.fullscreenElement) {
      return;
    }

    if (event.clientY === 0) {
      this.showToolbarDiv = true;
    } else if (event.clientY > 44) {
      this.showToolbarDiv = false;
    }
  }
}
