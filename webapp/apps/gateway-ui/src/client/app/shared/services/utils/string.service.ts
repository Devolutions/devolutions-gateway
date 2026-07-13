export interface ExtractedUsernameDomain {
  username: string;
  domain: string;
}

export interface ExtractedHostnamePort {
  hostname: string;
  port: number;
}

export class StringService {
  constructor() {}

  //DOMAIN\username
  extractDomain(fullUsername: string): ExtractedUsernameDomain {
    const extractionData: ExtractedUsernameDomain = {
      username: fullUsername,
      domain: '',
    };

    if (fullUsername.includes('\\')) {
      extractionData.domain = fullUsername.split('\\')[0];
      extractionData.username = fullUsername.split('\\')[1];
    }
    return extractionData;
  }

  // const urlWithPort = ensurePort('http://example.com'); // Will add ':88'
  // const urlWithExistingPort = ensurePort('http://example.com:1234'); // Will remain unchanged
  ensurePort(url: string, defaultPort = ':88'): string {
    if (!url) {
      return '';
    }
    const portRegex = /:\d+$/;

    if (portRegex.test(url)) {
      return url;
    }
    return `${url}${defaultPort}`;
  }

  extractHostnameAndPort(urlString: string, defaultPort: number): ExtractedHostnamePort {
    const input = urlString.trim();

    if (!input) {
      return null;
    }

    if (/^[a-z][a-z\d+.-]*:\/\//i.test(input)) {
      try {
        const url = new URL(input);

        return {
          hostname: url.hostname.replace(/^\[|\]$/g, ''),
          port: url.port ? Number.parseInt(url.port, 10) : defaultPort,
        };
      } catch {
        // Fall through to host[:port] parsing if URL parsing fails.
      }
    }

    const bracketedIpv6Match = input.match(/^\[([^\]]+)](?::(\d+))?$/);

    if (bracketedIpv6Match) {
      return {
        hostname: bracketedIpv6Match[1],
        port: bracketedIpv6Match[2] ? Number.parseInt(bracketedIpv6Match[2], 10) : defaultPort,
      };
    }

    const hostPortMatch = input.match(/^([^:]+):(\d+)$/);

    if (hostPortMatch) {
      return {
        hostname: hostPortMatch[1],
        port: Number.parseInt(hostPortMatch[2], 10),
      };
    }

    return {
      hostname: input,
      port: defaultPort,
    };
  }

  replaceNewlinesWithBR(text: string): string {
    return text.replace(/\n/g, '<br>');
  }
}
