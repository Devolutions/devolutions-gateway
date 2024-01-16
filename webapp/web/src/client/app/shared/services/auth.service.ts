import { Injectable } from '@angular/core';

import {Observable, of} from 'rxjs';
import {tap, takeUntil, map, catchError} from 'rxjs/operators';
import {BaseComponent} from "@shared/bases/base.component";
import {ApiService} from "@shared/services/api.service";

@Injectable({
  providedIn: 'root',
})
export class AuthService extends BaseComponent {
  constructor(private apiService: ApiService) {
    super();
  }
  isLoggedIn: boolean = false;

  //TODO Proper checks and error handling for login
  login(username: string, password: string): Observable<boolean> {
    return this.requestToken(username, password).pipe(
      takeUntil(this.destroyed$),
      tap((isLoggedIn) => (this.isLoggedIn = isLoggedIn))
    );
  }

  private requestToken(username: string, password: string): Observable<boolean> {
    return this.apiService.generateAppToken(username, password)
      .pipe(
        takeUntil(this.destroyed$),
        tap(response => this.storeAppToken(response)),
        map(() => true),
        catchError(error => {
          console.error('Error occurred during token request:', error);
          return of(false);
        })
      )
  }

  private storeAppToken(token: string): void {
    this.storeToken('appToken', token);
  }

  private storeSessionToken(token: string): void {
    this.storeToken('sessionToken', token);
  }

  //TODO Where are we storing this token?
  private storeToken(tokenName: string, token: string): void {
    localStorage.setItem(tokenName, token);
  }
}
