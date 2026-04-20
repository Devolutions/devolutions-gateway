import { FreePosition, ToolbarPosition } from '../models/floating-session-toolbar-config.model';

/**
 * Clamps (x, y) so the toolbar stays fully inside the positioning container.
 * If the toolbar is wider/taller than the container it pins to the 0 edge,
 * ensuring the drag handle is always reachable.
 */
export function clampPosition(x: number, y: number, toolbarEl: HTMLElement, containerRect: DOMRect): FreePosition {
  const toolbarRect = toolbarEl.getBoundingClientRect();
  return {
    x: Math.max(0, Math.min(containerRect.width - toolbarRect.width, x)),
    y: Math.max(0, Math.min(containerRect.height - toolbarRect.height, y)),
  };
}

/**
 * Returns true when the mouse is close enough to the toolbar to recall it
 * from auto-hide. Uses center-distance in free mode and edge-relative
 * proximity in docked mode.
 */
export function isNearToolbar(
  event: MouseEvent,
  toolbarMode: 'docked' | 'free',
  toolbarPosition: ToolbarPosition,
  toolbarEl: HTMLElement | null,
  containerRect: DOMRect,
  proximityDocked: number,
  proximityFree: number,
): boolean {
  if (toolbarMode === 'free') {
    if (!toolbarEl) return false;
    const rect = toolbarEl.getBoundingClientRect();
    const cx = rect.left + rect.width / 2;
    const cy = rect.top + rect.height / 2;
    return Math.sqrt((event.clientX - cx) ** 2 + (event.clientY - cy) ** 2) < proximityFree;
  }

  switch (toolbarPosition) {
    case 'top':
      return event.clientY < containerRect.top + proximityDocked;
    case 'bottom':
      return event.clientY > containerRect.bottom - proximityDocked;
    case 'left':
      return event.clientX < containerRect.left + proximityDocked;
    case 'right':
      return event.clientX > containerRect.right - proximityDocked;
    default:
      return false;
  }
}

/** Sizes for the four dock dropzone targets — must match the CSS in _dropzones.scss. */
export interface DropzoneSizes {
  hWidth: number; // horizontal pill width
  hHeight: number; // horizontal pill height
  vWidth: number; // vertical pill width
  vHeight: number; // vertical pill height
  margin: number; // distance from container edge
}

/**
 * Computes the viewport-relative bounding rect for each of the four
 * dock dropzone targets based on the container rect and CSS-matched sizes.
 */
export function getDropzoneRects(
  containerRect: DOMRect,
  sizes: DropzoneSizes,
): Record<ToolbarPosition, { left: number; top: number; right: number; bottom: number }> {
  const { hWidth, hHeight, vWidth, vHeight, margin } = sizes;
  return {
    top: {
      left: containerRect.left + (containerRect.width - hWidth) / 2,
      top: containerRect.top + margin,
      right: containerRect.left + (containerRect.width + hWidth) / 2,
      bottom: containerRect.top + margin + hHeight,
    },
    bottom: {
      left: containerRect.left + (containerRect.width - hWidth) / 2,
      top: containerRect.bottom - margin - hHeight,
      right: containerRect.left + (containerRect.width + hWidth) / 2,
      bottom: containerRect.bottom - margin,
    },
    left: {
      left: containerRect.left + margin,
      top: containerRect.top + (containerRect.height - vHeight) / 2,
      right: containerRect.left + margin + vWidth,
      bottom: containerRect.top + (containerRect.height + vHeight) / 2,
    },
    right: {
      left: containerRect.right - margin - vWidth,
      top: containerRect.top + (containerRect.height - vHeight) / 2,
      right: containerRect.right - margin,
      bottom: containerRect.top + (containerRect.height + vHeight) / 2,
    },
  };
}
