import {UtilsService} from '../utils.service';

export interface ExtractedUsernameDomain {
  username: string,
  domain: string
}

export interface ExtractedHostnamePort {
  hostname: string,
  port: number
}

export class StringService {

  private utils: UtilsService;

  constructor(parent: UtilsService) {
    this.utils = parent;
  }

  //DOMAIN\username or username@DOMAIN
  extractDomain(fullUsername: string): ExtractedUsernameDomain {
    const extractionData: ExtractedUsernameDomain = {
      username: fullUsername,
      domain: ''
    };

    if (fullUsername.includes('\\')) {
      extractionData.domain = fullUsername.split('\\')[0];
      extractionData.username = fullUsername.split('\\')[1];
    } else if (fullUsername.includes('@')) {
      extractionData.domain = fullUsername.split('@')[1];
      extractionData.username = fullUsername.split('@')[0];
    }
    return extractionData;
  }

  // const urlWithPort = ensurePort('http://example.com'); // Will add ':88'
  // const urlWithExistingPort = ensurePort('http://example.com:1234'); // Will remain unchanged
  ensurePort(url: string, defaultPort: string = ':88'): string {
    if (!url) {
      return '';
    }
    const portRegex = /:\d+$/;

    if (portRegex.test(url)) {
      return url;
    } else {
      return `${url}${defaultPort}`;
    }
  }

  extractHostnameAndPort(urlString: string, DefaultPort: number): ExtractedHostnamePort {
    // This regex assumes the URL might start with a protocol and captures hostname and optional port
    const regex = /^(?:.*:\/\/)?([^:/]+)(?::(\d+))?/;
    const match = urlString.match(regex);

    if (match) {
      const hostname: string = match[1];
      const port: number = match[2] ? parseInt(match[2], 10) : DefaultPort;
      return { hostname, port };
    } else {
      return null;
    }
  }

}
