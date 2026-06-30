import { Injectable, OnDestroy, Renderer2, RendererFactory2 } from '@angular/core';
import { BehaviorSubject, fromEvent, Observable, Subject } from 'rxjs';
import { distinctUntilChanged, takeUntil } from 'rxjs/operators';
import { StorageService } from './utils/storage.service';

export type Theme = 'default' | 'dark' | 'light';
export type EffectiveTheme = 'dark' | 'light';

const THEME_STORAGE_KEY = 'gateway.theme';

@Injectable({
  providedIn: 'root',
})
export class ThemeService implements OnDestroy {
  readonly currentThemeObservable: Observable<Theme>;
  readonly effectiveThemeObservable: Observable<EffectiveTheme>;

  private readonly destroyed$ = new Subject<void>();
  private readonly darkScheme: MediaQueryList = window.matchMedia('(prefers-color-scheme: dark)');
  private readonly renderer: Renderer2;
  private readonly currentThemeSubject: BehaviorSubject<Theme>;
  private readonly effectiveThemeSubject: BehaviorSubject<EffectiveTheme>;

  constructor(
    rendererFactory: RendererFactory2,
    private readonly storageService: StorageService,
  ) {
    this.renderer = rendererFactory.createRenderer(null, null);

    const initialTheme = this.getStoredTheme();
    this.currentThemeSubject = new BehaviorSubject<Theme>(initialTheme);
    this.effectiveThemeSubject = new BehaviorSubject<EffectiveTheme>(this.resolveEffectiveTheme(initialTheme));
    this.currentThemeObservable = this.currentThemeSubject.asObservable();
    this.effectiveThemeObservable = this.effectiveThemeSubject.asObservable();

    this.applyTheme(initialTheme);

    this.currentThemeSubject.pipe(distinctUntilChanged(), takeUntil(this.destroyed$)).subscribe((theme) => {
      this.persistTheme(theme);
      this.applyTheme(theme);
    });

    fromEvent<MediaQueryListEvent>(this.darkScheme, 'change')
      .pipe(takeUntil(this.destroyed$))
      .subscribe(() => {
        if (this.currentTheme === 'default') {
          this.applyTheme('default');
        }
      });
  }

  get currentTheme(): Theme {
    return this.currentThemeSubject.getValue();
  }

  set currentTheme(theme: Theme) {
    this.currentThemeSubject.next(theme);
  }

  get effectiveTheme(): EffectiveTheme {
    return this.effectiveThemeSubject.getValue();
  }

  get isDarkTheme(): boolean {
    return this.effectiveTheme === 'dark';
  }

  initialize(): void {
    this.applyTheme(this.currentTheme);
  }

  toggleTheme(): void {
    this.currentTheme = this.isDarkTheme ? 'light' : 'dark';
  }

  resetTheme(): void {
    this.currentTheme = 'default';
  }

  ngOnDestroy(): void {
    this.destroyed$.next();
    this.destroyed$.complete();
  }

  private getStoredTheme(): Theme {
    const storedTheme = this.storageService.getItem<Theme>(THEME_STORAGE_KEY);

    if (!this.isTheme(storedTheme)) {
      this.storageService.removeItem(THEME_STORAGE_KEY);
      return 'default';
    }

    return storedTheme;
  }

  private persistTheme(theme: Theme): void {
    if (theme === 'default') {
      this.storageService.removeItem(THEME_STORAGE_KEY);
      return;
    }

    this.storageService.setItem(THEME_STORAGE_KEY, theme);
  }

  private applyTheme(theme: Theme): void {
    const effectiveTheme = this.resolveEffectiveTheme(theme);
    const inactiveTheme = effectiveTheme === 'dark' ? 'light' : 'dark';

    for (const element of [document.documentElement, document.body]) {
      this.renderer.removeClass(element, `${inactiveTheme}-theme`);
      this.renderer.addClass(element, `${effectiveTheme}-theme`);
      this.renderer.setAttribute(element, 'data-theme', effectiveTheme);
    }

    this.effectiveThemeSubject.next(effectiveTheme);
  }

  private resolveEffectiveTheme(theme: Theme): EffectiveTheme {
    return theme === 'dark' || (theme === 'default' && this.darkScheme.matches) ? 'dark' : 'light';
  }

  private isTheme(theme: Theme | null): theme is Theme {
    return theme === 'default' || theme === 'dark' || theme === 'light';
  }
}
