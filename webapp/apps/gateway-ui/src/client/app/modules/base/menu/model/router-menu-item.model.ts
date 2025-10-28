interface IRouterMenuItem {
  label: string;
  icon: string;
  action: () => void;
  isSelectedFn?: (url: string) => boolean;
  blockClickSelected?: boolean;
}

export class RouterMenuItem {
  public label: string;
  public icon: string;
  public blockClickSelected: boolean;
  private _action: () => void;
  private readonly _isSelectedFn?: (url: string) => boolean;
  private _selected = false;

  constructor(data: IRouterMenuItem) {
    this.label = data.label;
    this.icon = data.icon;
    this._action = data.action;
    this._isSelectedFn = data.isSelectedFn;
    this.blockClickSelected = data.blockClickSelected ?? false;
  }

  public get selected(): boolean {
    return this._selected;
  }

  public executeAction(): void {
    this._action.call(this);
  }

  public setSelected(url: string): void {
    this._selected = this._isSelectedFn?.(url) ?? false;
  }
}

/*
export class RouterMenuItem {

  selected: boolean = false;
  label: string;
  icon: string;
  action: () => void;
  isSelectedFn ?: (url: string) => boolean;
  blockClickSelected: boolean = false;

  constructor(data: IRouterMenuItem) {
    this.label = data.label;
    this.icon = data.icon;
    this.action = data.action.bind(this);
    this.isSelectedFn = data.isSelectedFn;
    this.blockClickSelected = data.blockClickSelected;
  }

  setSelected(url: string) {
    this.selected = this.isSelectedFn(url);
  }
}

interface IRouterMenuItem {
  label: string;
  icon: string;
  action: () => void;
  isSelectedFn?: (url: string) => boolean;
  blockClickSelected?: boolean;
}
*/
