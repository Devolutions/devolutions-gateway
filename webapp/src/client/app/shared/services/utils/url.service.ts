import { UtilsService } from '../utils.service';

export class UrlService {
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

      if (closingBracketIndex !== -1 && url.length > closingBracketIndex + 1 && url[closingBracketIndex + 1] === ':') {
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
    }
    return address;
  }
}
