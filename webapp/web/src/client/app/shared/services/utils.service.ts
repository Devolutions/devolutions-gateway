import {Injectable} from '@angular/core';
import {UrlService} from './utils/url.service';


@Injectable({providedIn: 'root'})
export class UtilsService {
  url: UrlService = new UrlService(this);

  constructor() { }
}
