// src/client/app/shared/directives/tooltip-ellipsis.directive.ts
import { AfterViewInit, Directive, ElementRef, Injector, NgZone, OnDestroy } from '@angular/core';
import { BaseComponent } from '@shared/bases/base.component';
import { Tooltip } from 'primeng/tooltip';

@Directive({
  standalone: false,
  selector: '[tooltipEllipsis]',
})
export class TooltipEllipsisDirective extends BaseComponent implements AfterViewInit, OnDestroy {
  private resizeObserver!: ResizeObserver;
  private tooltipInstance: Tooltip | null = null;

  constructor(
    private el: ElementRef,
    private injector: Injector, // <- use Injector instead of direct Tooltip
    private zone: NgZone,
  ) {
    super();
  }

  ngAfterViewInit(): void {
    // Lazily resolve Tooltip to avoid circular DI during module hydration.
    // This returns the host Tooltip directive instance if present, or null if not found.
    try {
      this.tooltipInstance = this.injector.get(Tooltip, null);
    } catch {
      this.tooltipInstance = null;
    }

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
    if (!this.tooltipInstance) {
      return;
    }

    const shouldBeDisabled = !this.isEllipsisActive();

    // primeNG Tooltip has setOption; `disabled` may be internal — guard access.
    interface TooltipWithOptions {
      disabled?: boolean;
      setOption?: (options: { disabled: boolean }) => void;
    }
    const tooltip = this.tooltipInstance as unknown as TooltipWithOptions;
    const currentDisabled = tooltip?.disabled;
    if (shouldBeDisabled !== currentDisabled) {
      this.zone.run(() => {
        // use setOption if available; otherwise, try setting `disabled` directly as a fallback
        if (typeof tooltip?.setOption === 'function') {
          tooltip.setOption({ disabled: shouldBeDisabled });
        } else {
          tooltip.disabled = shouldBeDisabled;
        }
      });
    }
  }

  private isEllipsisActive(): boolean {
    const el = this.el.nativeElement as HTMLElement;
    return el.offsetWidth < el.scrollWidth;
  }
}
