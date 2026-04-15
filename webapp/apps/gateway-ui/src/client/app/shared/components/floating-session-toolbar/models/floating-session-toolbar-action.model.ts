/** A single action entry rendered in the toolbar dropdown.
 *  The `icon` field is an opaque CSS class string — the caller supplies
 *  whatever icon system their app uses (e.g. 'dvl-icon dvl-icon-copy'). */
export interface ToolbarAction {
  /** Stable key for track-by. Optional during migration — will become required
   *  once all consumers are fully migrated away from ClipboardActionButton. */
  id?: string;
  label: string;
  tooltip: string;
  icon: string;
  action: () => void | Promise<void>;
  enabled: () => boolean;
  /** Optional grouping key rendered as a dropdown section heading. */
  section?: string;
}

/** Backward-compat alias — remove once all consumers have migrated to ToolbarAction. */
export type ClipboardActionButton = ToolbarAction;
