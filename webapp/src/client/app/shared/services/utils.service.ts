import { Injectable } from '@angular/core';
import { StringService } from '@shared/services/utils/string.service';
import { UrlService } from './utils/url.service';

@Injectable({ providedIn: 'root' })
export class UtilsService {
  url: UrlService = new UrlService();
  string: StringService = new StringService();

  constructor() {}
}
