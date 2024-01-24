import {Injectable} from '@angular/core';
import {UrlService} from './utils/url.service';
import {StringService} from "@shared/services/utils/string.service";


@Injectable({providedIn: 'root'})
export class UtilsService {
  url: UrlService = new UrlService(this);
  string: StringService = new StringService(this);

  constructor() { }
}
