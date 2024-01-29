import {UtilsService} from '../utils.service';

interface ExtractionUsernameDomain {
  username: string,
  domain: string
}

export class StringService {

  private utils: UtilsService;

  constructor(parent: UtilsService) {
    this.utils = parent;
  }

  //DOMAIN\username or username@DOMAIN
  extractDomain(fullUsername: string): ExtractionUsernameDomain {
    const extractionData: ExtractionUsernameDomain = {
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

}
