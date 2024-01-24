import {UtilsService} from '../utils.service';

export class StringService {

  private utils: UtilsService;

  constructor(parent: UtilsService) {
    this.utils = parent;
  }

  extractDomain(host): string {
    let domain: string;

    if (host.includes('/')) {
      domain = host.split('/')[1];
    } else if (host.includes('@')) {
      domain = host.split('@')[1];
    }
    return domain;
  }

}
