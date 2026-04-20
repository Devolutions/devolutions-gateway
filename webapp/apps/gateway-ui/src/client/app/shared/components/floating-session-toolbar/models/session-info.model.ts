export type SessionInfoValue = string | number | boolean | null | undefined;

export type SessionInfoRowId = string;

export interface ToolbarSessionInfoRow {
  id: SessionInfoRowId;
  label: string;
  value: SessionInfoValue;
  order?: number;
  hidden?: boolean;
  copyable?: boolean;
  monospace?: boolean;
  tone?: 'default' | 'muted' | 'success' | 'warning' | 'danger';
}

export interface ToolbarSessionInfo {
  title?: string;
  rows: ToolbarSessionInfoRow[];
  emptyValueText?: string;
}

export interface ToolbarSessionInfoTemplateContext {
  $implicit: ToolbarSessionInfo;
  sessionInfo: ToolbarSessionInfo;
  rows: ToolbarSessionInfoRow[];
  resolveValue: (row: ToolbarSessionInfoRow) => string;
}
