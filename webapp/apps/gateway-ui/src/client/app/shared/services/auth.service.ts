import { Injectable } from '@angular/core';
import { BaseComponent } from '@shared/bases/base.component';
import { Session } from '@shared/models/session';
import { ApiService } from '@shared/services/api.service';
import { NavigationService } from '@shared/services/navigation.service';
import { WebSessionService } from '@shared/services/web-session.service';
import { BehaviorSubject, interval, Observable, of, Subscription, throwError } from 'rxjs';
import { catchError, map, takeUntil, tap } from 'rxjs/operators';

@Injectable({
  providedIn: 'root',
})
export class AuthService extends BaseComponent {
  private static readonly TOKEN_LIFESPAN: number = 8 * 60 * 60 * 1000; // app token lasts (default is 28800 for 8 hours)
  private static readonly SESSION_STORAGE_KEY: string = 'session';
  private static readonly AUTO_LOGIN_KEY: string = 'autologin';

  private expirationCheckInterval = 60000; // Check every 60 seconds
  private expirationCheckSubscription: Subscription | null = null;

  private sessionSubject: BehaviorSubject<Session | null>;
  public session: Observable<Session | null>;

  isAutoLoginOn: BehaviorSubject<boolean> = new BehaviorSubject(false);

  constructor(
    private apiService: ApiService,
    private webSessionService: WebSessionService,
    private navigationService: NavigationService,
  ) {
    super();

    this.initializeSessionStorageData();
    this.initializeAutoLogonStorageData();
  }

  public get sessionValue() {
    return this.sessionSubject.value;
  }

  public get isAuthenticated(): boolean {
    const sessionData: string = sessionStorage.getItem(AuthService.SESSION_STORAGE_KEY);
    if (!sessionData) {
      return false;
    }

    const session: Session = JSON.parse(sessionData);
    return this.isSessionValid(session);
  }

  public autoLogin(): Observable<boolean> {
    if (this.checkSessionState()) {
      return of(true);
    }

    return this.login().pipe(
      takeUntil(this.destroyed$),
      tap((success) => {
        sessionStorage.setItem(AuthService.AUTO_LOGIN_KEY, JSON.stringify(success));
        this.isAutoLoginOn.next(success);
      }),
      catchError((error) => {
        sessionStorage.setItem(AuthService.AUTO_LOGIN_KEY, JSON.stringify(false));
        this.isAutoLoginOn.next(false);
        return throwError(() => error);
      }),
      map((success) => !!success),
    );
  }

  login(username?: string, password?: string): Observable<boolean> {
    return this.requestToken(username, password).pipe(
      takeUntil(this.destroyed$),
      tap((token) => {
        if (token) {
          this.storeToken(username, token);
        }
      }),
      map((token) => !!token),
      catchError((error) => {
        return throwError(() => error);
      }),
    );
  }

  public logout(): void {
    void this.webSessionService.cleanupWebSessionService();
    this.removeAllStorageData();
    this.sessionSubject.next(null);
    this.isAutoLoginOn.next(false);
    void this.navigationService.navigateToLogin();
  }

  public startExpirationCheck(): void {
    if (this.expirationCheckSubscription) {
      this.expirationCheckSubscription.unsubscribe();
    }
    this.expirationCheckSubscription = interval(this.expirationCheckInterval).subscribe(() => {
      if (!this.isAuthenticated) {
        this.handleTokenExpiration();
      }
    });
  }

  public stopExpirationCheck(): void {
    if (this.expirationCheckSubscription) {
      this.expirationCheckSubscription.unsubscribe();
      this.expirationCheckSubscription = null;
    }
  }

  private requestToken(username?: string, password?: string): Observable<string> {
    return this.apiService.generateAppToken(username, password).pipe(
      catchError((error) => {
        return throwError(() => error);
      }),
    );
  }

  private initializeAutoLogonStorageData(): void {
    const storedAutoLogonFlag: string = sessionStorage.getItem(AuthService.AUTO_LOGIN_KEY);
    const storedAutoLogon: boolean = storedAutoLogonFlag ? storedAutoLogonFlag !== 'false' : false;
    this.isAutoLoginOn.next(storedAutoLogon);
  }

  private initializeSessionStorageData(): void {
    const storedSessionData: string = sessionStorage.getItem(AuthService.SESSION_STORAGE_KEY);
    const storedSession = storedSessionData ? JSON.parse(storedSessionData) : null;

    this.sessionSubject = new BehaviorSubject<Session | null>(storedSession);
    this.session = this.sessionSubject.asObservable();

    this.checkSessionState();
  }

  private storeToken(username: string, token: string): void {
    const expirationTime: number = Date.now() + AuthService.TOKEN_LIFESPAN;
    const session: Session = new Session(username, token, new Date(expirationTime).toISOString());
    sessionStorage.setItem(AuthService.SESSION_STORAGE_KEY, JSON.stringify(session));
    this.sessionSubject.next(session);
  }

  removeAllStorageData(): void {
    sessionStorage.removeItem(AuthService.SESSION_STORAGE_KEY);
    sessionStorage.removeItem(AuthService.AUTO_LOGIN_KEY);
  }

  private checkSessionState(): boolean {
    const session: Session = this.getStoredSession();
    if (session && this.isSessionValid(session)) {
      this.sessionSubject.next(session);
      return true;
    }
    return false;
  }

  private getStoredSession(): Session | null {
    const sessionData: string = sessionStorage.getItem(AuthService.SESSION_STORAGE_KEY);
    if (!sessionData) {
      return null;
    }

    try {
      return JSON.parse(sessionData) as Session;
    } catch (error) {
      console.error('Error parsing session data:', error);
      return null;
    }
  }

  private isSessionValid(session: Session | null): boolean {
    if (!session || !session.expires) {
      return false;
    }

    const now: number = Date.now();
    const expiresTime: number = new Date(session.expires).getTime();

    return now <= expiresTime;
  }

  private handleTokenExpiration(): void {
    void this.webSessionService.cleanupWebSessionService();
    this.removeAllStorageData();
    void this.navigationService.navigateToLogin();
  }
}
