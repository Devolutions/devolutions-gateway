import { Injectable } from '@angular/core';
import {Router} from "@angular/router";
import {BehaviorSubject, interval, Observable, of, Subscription} from 'rxjs';
import {tap, takeUntil, map, catchError} from 'rxjs/operators';

import {BaseComponent} from "@shared/bases/base.component";
import {ApiService} from "@shared/services/api.service";
import {Session} from "@shared/models/session";

@Injectable({
  providedIn: 'root',
})
export class AuthService extends BaseComponent {
  //TODO app token lasts (default is 28800 for 8 hours)
  //user a shorter time period for development
  private static readonly TOKEN_LIFESPAN: number = 10 * 60 * 1000; // 10 minutes in milliseconds
  private static readonly SESSION_STORAGE_KEY: string = 'session';

  private expirationCheckInterval: number = 60000; // Check every 60 seconds
  private expirationCheckSubscription: Subscription | null = null;

  private sessionSubject: BehaviorSubject<Session | null>;
  public session: Observable<Session | null>;
  isLoggedIn: boolean = false;

  constructor(
    private router: Router,
    private apiService: ApiService
  ) {
    super();
    const storedSessionData: string = sessionStorage.getItem(AuthService.SESSION_STORAGE_KEY);
    const storedSession = storedSessionData ? JSON.parse(storedSessionData) : null;

    this.sessionSubject = new BehaviorSubject<Session | null>(storedSession);
    this.session = this.sessionSubject.asObservable();
    this.checkInitialSessionState();
  }

  public get sessionValue() {
    return this.sessionSubject.value;
  }

  public get isAuthenticated(): boolean {
    const sessionData: string = sessionStorage.getItem('session');
    if (!sessionData) {
      return false;
    }

    const session: Session = JSON.parse(sessionData);
    return this.isSessionValid(session);
  }

  public login(username: string, password: string): Observable<boolean> {
    return this.requestToken(username, password).pipe(
      takeUntil(this.destroyed$),
      tap((isLoggedIn) => (this.isLoggedIn = isLoggedIn)),
      catchError(error => {
        console.error('Login error:', error);
        return of(false);
      })
    );
  }

  public logout(): void {
    sessionStorage.removeItem(AuthService.SESSION_STORAGE_KEY);
    this.sessionSubject.next(null);
    this.router.navigate(['login']);
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

  private requestToken(username: string, password: string): Observable<boolean> {
    return this.apiService.generateAppToken(username, password)
      .pipe(
        takeUntil(this.destroyed$),
        tap(response => this.storeToken(username, response)),
        map(() => true),
        catchError(error => {
          console.error('Error requesting token:', error);
          return of(false);
        })
      )
  }

  private storeToken(username: string, token: string): void {
    const expirationTime: number = new Date().getTime() + AuthService.TOKEN_LIFESPAN;
    const session: Session = new Session(username, token, new Date(expirationTime).toISOString());
    sessionStorage.setItem(AuthService.SESSION_STORAGE_KEY, JSON.stringify(session));
    this.sessionSubject.next(session);
  }

  private checkInitialSessionState(): void {
    const session: Session = this.getStoredSession();
    if (session && this.isSessionValid(session)) {
      this.isLoggedIn = true;
      this.sessionSubject.next(session);
    }
  }

  private getStoredSession(): Session | null {
    const sessionData = sessionStorage.getItem(AuthService.SESSION_STORAGE_KEY);
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

    const now: number = new Date().getTime();
    const expiresTime: number = new Date(session.expires).getTime();

    return now <= expiresTime;
  }

  private handleTokenExpiration(): void {
    sessionStorage.removeItem('session');
    this.router.navigate(['/login'], { queryParams: { expired: true } });
  }
}
