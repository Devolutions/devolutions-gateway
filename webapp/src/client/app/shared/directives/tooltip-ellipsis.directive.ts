import { AfterViewInit, Directive, ElementRef, NgZone, OnDestroy } from '@angular/core';
import { BaseComponent } from '@shared/bases/base.component';
import { Tooltip } from 'primeng/tooltip';

@Directive({
  selector: '[tooltipEllipsis]',
})
export class TooltipEllipsisDirective extends BaseComponent implements AfterViewInit, OnDestroy {
  private resizeObserver: ResizeObserver;

  constructor(
    private el: ElementRef,
    private tooltip: Tooltip,
    private zone: NgZone,
  ) {
    super();
  }

  ngAfterViewInit(): void {
    this.setupResizeObserver();
  }

  ngOnDestroy(): void {
    if (this.resizeObserver) {
      this.resizeObserver.disconnect();
    }
  }

  private setupResizeObserver(): void {
    this.zone.runOutsideAngular(() => {
      // Each entry in the array represents a different instance of the observed changes
      this.resizeObserver = new ResizeObserver((entries) => {
        // Since our `isEllipsisActive` logic depend on scroll overflow information that we must query
        // on the dom element itself because it is not conveyed in `ResizeObserverEntry`, if multiple
        // resize entries were queued up, we are only interested in the last one.
        // Also, since we don't need the `ResizeObserverEntry` itself, instead of fetching
        // the last one, we can just check for the existence of at least one of them.
        if (entries?.length > 0) {
          this.updateTooltipVisibility();
        }
      });
      // Start observing the specified element.
      this.resizeObserver.observe(this.el.nativeElement);
    });
  }

  private updateTooltipVisibility(): void {
    const shouldBeDisabled = !this.isEllipsisActive();
    if (shouldBeDisabled !== this.tooltip.disabled) {
      this.zone.run(() => {
        this.tooltip.setOption({ disabled: shouldBeDisabled });
      });
    }
  }

  private isEllipsisActive(): boolean {
    return this.el.nativeElement.offsetWidth < this.el.nativeElement.scrollWidth;
  }
}
