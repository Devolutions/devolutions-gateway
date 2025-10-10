import { Injectable } from '@angular/core';
import { merge, Observable, Subject, timer } from 'rxjs';
import { distinctUntilChanged, finalize, map, shareReplay, startWith, takeUntil } from 'rxjs/operators';
import { LoadingMode } from '../enums/loading-mode.enum';
import { LoadingEvent } from '../models/loading-event.model';

@Injectable()
export class LoadingService {
  DELAY_TO_SHOW_LOADING = 300;

  get mode(): LoadingMode {
    return this._mode;
  }

  set mode(value: LoadingMode) {
    this.clear();
    this._mode = value;
  }

  private _mode: LoadingMode;
  private readonly subject: Subject<LoadingEvent>;
  private workCounter: number;
  private readonly receivers: unknown[];

  public constructor() {
    this.receivers = [];
    this.subject = new Subject();

    this._mode = LoadingMode.Local;
    this.workCounter = 0;
  }

  public isWorking(): Subject<LoadingEvent> {
    return this.subject;
  }

  public clear() {
    this.workCounter = 0;
    this.pushValue();
  }

  public addWork() {
    this.workCounter++;
    this.pushValue();
  }

  public removeWork() {
    if (this.workCounter > 0) {
      this.workCounter--;
    }

    this.pushValue();
  }

  public addReceiver(receiver) {
    this.receivers.push(receiver);
  }

  public removeReceiver(receiver) {
    const index = this.receivers.indexOf(receiver);
    if (index > -1) {
      this.receivers.splice(index, 1);
    }
  }

  /* Usage: .pipe(indicate(this.yourLoadingSubject$)) */
  public indicate<T>(indicator: Subject<boolean>): (source: Observable<T>) => Observable<T> {
    return (source: Observable<T>): Observable<T> =>
      source.pipe(
        shareReplay(1),
        this.prepare((visible: boolean) => indicator.next(visible)),
        finalize(() => indicator.next(false)),
      );
  }

  private pushValue() {
    this.subject.next({
      isLoading: this.workCounter > 0,
      receiver: this.getCurrentReceiver(),
      mode: this._mode,
    });
  }

  private getCurrentReceiver() {
    return this.receivers.length ? this.receivers[this.receivers.length - 1] : null;
  }

  private prepare<T>(callback: (visible) => void): (source: Observable<T>) => Observable<T> {
    return (source: Observable<T>): Observable<T> => {
      merge(
        timer(this.DELAY_TO_SHOW_LOADING).pipe(
          map(() => true),
          takeUntil(source),
        ), // 1 sec delay before displaying loading spinner
        source.pipe(map(() => false)),
      )
        .pipe(startWith(false), distinctUntilChanged())
        .subscribe((visible: boolean) => callback(visible));

      return source;
    };
  }
}
