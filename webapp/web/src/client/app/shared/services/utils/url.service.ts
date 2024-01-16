import {UtilsService} from '../utils.service';
import {noop} from 'rxjs';
import {ConfirmationService} from 'primeng/api';
import {GatewayMessageService} from "@shared/components/gateway-message/gateway-message.service";

export class UrlService {

  private utils: UtilsService;

  constructor(parent: UtilsService) {
    this.utils = parent;
  }

  trimPortFromUrl(url: string): string {
    if (!url || url === '') {
      return url;
    }

    const arrUrl = url.split(':');
    // Too many ":"; must be an IPv6
    if (arrUrl.length > 4) {
      const closingBracketIndex = url.lastIndexOf(']');

      if ((closingBracketIndex !== -1) && (url.length > (closingBracketIndex + 1))
        && (url[closingBracketIndex + 1] === ':')) {
        return url.substr(0, closingBracketIndex + 1);
      }

      return url;
    }

    const index = url.lastIndexOf(':');
    if (index >= 0) {
      // Two ":" in a row; must be a VNC address. - Hubert 2016-04-01
      if (arrUrl.length === 4 && url.indexOf('::') >= 0) {
        return url.substr(0, index - 1);
      }

      return url.substr(0, index);
    }

    return url;
  }

  formatHostsFromString(hosts: string) {
    return hosts.replace(/\n/g, ', ');
  }

  concatAddressAndPort(address: string, port: number) {
    if (port !== 0) {
      return address + ':' + port;
    } else {
      return address;
    }
  }

  openInNewTab(value: string, confirmationService: ConfirmationService, gatewayMessageService: GatewayMessageService, incognito: boolean = false) {
    try {
      let features = 'noreferrer'; // Noreferrer is a security setting to block XSS (via noopener).

      if (incognito) {
        features = 'incognito,' + features;
      }

      if (!value.includes('://')) {
        window.open('https://' + value, '_blank', features);
      } else if (value.includes('http://') || value.includes('https://')) {
        window.open(value, '_blank', features);
      } else {
        confirmationService.confirm({
          key: 'openDangerousWebsiteLink',
          message: 'The URL doesn\'t start with http:// or https://. Do you want to continue?',
          accept: () => window.open(value, '_blank', features),
          reject: () => noop()
        });
      }
    } catch (e) {
      gatewayMessageService.addError('Invalid url');
    }
  }
}
