// Class for Web App login session
export class Session {
  username?: string;
  token?: string;
  expires?: string;

  constructor(username?: string, token?: string, expires?: string) {
    this.username = username;
    this.token = token;
    this.expires = expires;
  }
}
