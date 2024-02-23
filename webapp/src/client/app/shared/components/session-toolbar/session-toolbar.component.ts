import {Component, Input, ElementRef, Renderer2, HostListener} from '@angular/core';
import {UtilsService} from "@shared/services/utils.service";


@Component({
  selector: 'session-toolbar',
  templateUrl: 'session-toolbar.component.html',
  styleUrls: ['session-toolbar.component.scss']
})
export class SessionToolbarComponent {

  @Input() sessionContainerParent: ElementRef;

  @Input() leftButtons: {
    label: string;
    icon: string;
    action: Function }[] = [];

  @Input() middleButtons: {
    label: string;
    icon: string;
    action: Function }[] = [];

  @Input() rightButtons: {
    label: string;
    icon: string;
    action: Function }[] = [];

  isFullScreenMode: boolean = false;
  showToolbarDiv: boolean = true;
  loading: boolean = true;

  constructor(private renderer: Renderer2,
              protected utils: UtilsService) {
  }

  @HostListener('document:mousemove', ['$event'])
  onMouseMove(event: MouseEvent): void {
    this.handleSessionToolbarDisplay(event);
  }

  @HostListener('document:fullscreenchange')
  onFullScreenChange(): void {
    this.handleOnFullScreenEvent();
  }

  private handleOnFullScreenEvent(): void {
    if (!document.fullscreenElement) {
      this.handleExitFullScreenEvent()
    }
  }

  private handleSessionToolbarDisplay(event: MouseEvent): void {
    if (!document.fullscreenElement) {
      return;
    }

    if (event.clientY == 0) {
      this.showToolbarDiv = true;
    } else if (event.clientY > 44) {
      this.showToolbarDiv = false;
    }
  }

  toggleFullscreen(): void {
    this.isFullScreenMode = !this.isFullScreenMode;
    !document.fullscreenElement ? this.enterFullScreen() : this.exitFullScreen();
  }

  private async enterFullScreen(): Promise<void>  {
    if (document.fullscreenElement) {
      return;
    }

    try {
      const sessionContainerElement = this.sessionContainerParent.nativeElement;
      await sessionContainerElement.requestFullscreen();
    } catch (err: any) {
      this.isFullScreenMode = false;
      console.error(`Error attempting to enable fullscreen mode: ${err.message} (${err.name})`);
    }
  }

  private exitFullScreen(): void {
    if (document.fullscreenElement) {
      document.exitFullscreen().catch(err => {
        console.error(`Error attempting to exit fullscreen: ${err}`);
      });
    }
  }

  private handleExitFullScreenEvent(): void {
    this.isFullScreenMode = false;
    this.showToolbarDiv = true;

    const sessionContainerElement = this.sessionContainerParent.nativeElement;
    const sessionToolbarElement = sessionContainerElement.querySelector('#sessionToolbar');

    if (sessionToolbarElement) {
      this.renderer.removeClass(sessionToolbarElement, 'session-toolbar-layer');
    }
  }
}
