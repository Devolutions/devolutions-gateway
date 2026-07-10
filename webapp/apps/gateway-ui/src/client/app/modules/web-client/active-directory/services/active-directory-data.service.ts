import { Injectable, NgZone } from '@angular/core';
import init, {
  Attribute,
  AttributesArray,
  BinaryLdapModifies,
  LdapControl,
  LdapControlArray,
  LdapResult,
  LdapSession,
  LdapSessionParameters,
  LoggingLevel,
  ModifyRequest,
  SaslBindConfig,
  SearchParameters,
  SspiAuthMethod,
  set_logging_level,
} from '@devolutions/ldap-wasm-js';
import {
  AdAddRequest,
  AdBindRequest,
  AdBindResult,
  AdCapabilities,
  AdDataProvider,
  AdDeleteRequest,
  AdModifyDnRequest,
  AdModifyRequest,
  AdPageControl,
  AdPageResult,
  AdResult,
  AdSearchParams,
  AdSearchResult,
  LdapControlArrayLike,
  LdapResultLike,
  LdapSessionLike,
  normalizeError,
  SearchEntryLike,
  SearchMessageLike,
} from '@devolutions/web-active-directory-gui';
import { ActiveDirectorySessionStoreService } from './active-directory-session-store.service';

const LDAP_DECODER_MAX_BYTES = 32656;
const LDAP_PAGED_SEARCH_SIZE_LIMIT = 100000;

@Injectable()
export class ActiveDirectoryDataService implements AdDataProvider {
  private wasmInitialized = false;
  private wasmInitPromise: Promise<void> | null = null;

  constructor(
    private readonly zone: NgZone,
    private readonly sessionStore: ActiveDirectorySessionStoreService,
  ) {}

  async search(params: AdSearchParams): Promise<AdSearchResult> {
    const session = this.sessionStore.getSession();

    try {
      const result = await this.zone.runOutsideAngular(() =>
        session.search({
          search_base: params.baseDn,
          filter: params.filter,
          scope: params.scope,
          attributes: params.attributes || [],
          size_limit: undefined,
          time_limit: params.timeLimit,
          controls: params.controls,
        }),
      );

      const entries = this.extractSearchEntries(result.messages || []);

      return {
        entries,
        total: entries.length,
        nextCookie: null,
        control: undefined,
      };
    } catch (error) {
      throw normalizeError(error);
    }
  }

  async pagedSearch(ctrl: AdPageControl): Promise<AdPageResult> {
    const session = this.sessionStore.getSession();

    try {
      const controlsWithPaging: LdapControlArrayLike = [
        ...(ctrl.controls || []),
        {
          simple_paged_results: {
            size: ctrl.pageSize,
            cookie: ctrl.cookie ?? [],
          },
        },
      ];

      const result = await this.zone.runOutsideAngular(() =>
        session.search({
          search_base: ctrl.baseDn,
          filter: ctrl.filter,
          scope: ctrl.scope,
          attributes: ctrl.attributes || [],
          size_limit: LDAP_PAGED_SEARCH_SIZE_LIMIT,
          time_limit: ctrl.timeLimit,
          controls: controlsWithPaging,
        }),
      );

      const entries = this.extractSearchEntries(result.messages || []);
      const searchDone = result.messages?.find((message) => 'search_done' in message.op);
      const responseControl = searchDone?.ctrl ?? [];
      const pagedControl = responseControl.find(
        (ldapControl): ldapControl is { simple_paged_results: { size: number; cookie: number[] } } =>
          'simple_paged_results' in ldapControl,
      );
      const cookie = pagedControl?.simple_paged_results.cookie ?? [];

      return {
        entries,
        hasMore: cookie.length > 0,
        cookie,
        control: responseControl,
      };
    } catch (error) {
      throw normalizeError(error);
    }
  }

  async getCapabilities(): Promise<AdCapabilities> {
    return {
      canCreateUser: true,
      canCreateGroup: true,
      canResetPassword: true,
      canDelete: true,
    };
  }

  async connect(gatewayWsUrl: string): Promise<LdapSessionLike> {
    try {
      await this.initializeWasm();

      const ldapSession = await this.zone.runOutsideAngular(() =>
        LdapSession.connect(new LdapSessionParameters(gatewayWsUrl, LDAP_DECODER_MAX_BYTES)),
      );

      const wrappedSession: LdapSessionLike = {
        sasl_bind: async (args) => {
          const response = await this.zone.runOutsideAngular(() => ldapSession.sasl_bind(this.toSaslBindConfig(args)));

          return {
            res: response.res,
            serverSaslCredential: response.saslcreds,
          };
        },
        unbind: (ldapControl) =>
          this.zone.runOutsideAngular(() => ldapSession.unbind(this.toLdapControls(ldapControl))),
        search: async (args) => {
          const result = await this.zone.runOutsideAngular(() => ldapSession.search(this.toSearchParameters(args)));

          return {
            messages: result.messages.flatMap((message): SearchMessageLike[] => {
              if ('search_entry' in message.op) {
                return [{ op: { search_entry: message.op.search_entry }, ctrl: message.ctrl }];
              }

              if ('search_done' in message.op) {
                return [{ op: { search_done: message.op.search_done }, ctrl: message.ctrl }];
              }

              return [];
            }),
          };
        },
        modify: (dn, modifies, controls) =>
          this.zone.runOutsideAngular(() =>
            ldapSession.modify(dn, this.toBinaryLdapModifies(modifies), this.toLdapControls(controls)),
          ),
        modifyDn: (dn, newRdn, deleteOldRdn, newSuperior, controls) =>
          this.zone.runOutsideAngular(() =>
            ldapSession.modify_dn(dn, newRdn, deleteOldRdn, newSuperior, this.toLdapControls(controls)),
          ),
        delete: (dn, controls) =>
          this.zone.runOutsideAngular(() => ldapSession.delete(dn, this.toLdapControls(controls))),
        add: (dn, attributes, controls) =>
          this.zone.runOutsideAngular(() =>
            ldapSession.add(dn, this.toAttributesArray(attributes), this.toLdapControls(controls)),
          ),
      };

      this.sessionStore.setSession(wrappedSession);

      return wrappedSession;
    } catch (error) {
      throw normalizeError(error);
    }
  }

  async bind(req: AdBindRequest): Promise<AdBindResult> {
    try {
      const { domain, serverComputerName } = this.resolveDomainAndServerComputerName(
        req.domain,
        req.serverComputerName,
      );
      const response = await req.session.sasl_bind({
        username: req.username,
        password: req.password,
        auth_method: {
          negotiate: {
            domain,
            server_computer_name: serverComputerName,
            kdc_proxy_url: req.kdcProxyUrl,
          },
        },
        sign: req.sign,
        seal: req.seal,
        controls: undefined,
      });

      return response.res;
    } catch (error) {
      throw normalizeError(error);
    }
  }

  async unbind(session: LdapSessionLike, control?: LdapControlArrayLike): Promise<void> {
    try {
      await session.unbind(control);
      this.sessionStore.clearSession();
    } catch (error) {
      throw normalizeError(error);
    }
  }

  makeGatewayWsUrl(gatewayUrl: string | URL, sessionId: string, isLdaps: boolean, token?: string): string {
    const url = typeof gatewayUrl === 'string' ? new URL(gatewayUrl, window.location.href) : new URL(gatewayUrl.href);
    const forwardProtocol = isLdaps ? 'tls' : 'tcp';

    url.pathname = `${url.pathname.replace(/\/$/, '')}/${forwardProtocol}/${sessionId}`;
    url.search = token ? `?token=${token}` : '';
    url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';

    return url.href;
  }

  async addEntry(req: AdAddRequest): Promise<AdResult> {
    try {
      const result = await this.zone.runOutsideAngular(() => req.session.add(req.dn, req.attributes, req.controls));
      return this.toAdResult(result);
    } catch (error) {
      throw normalizeError(error);
    }
  }

  async deleteEntry(req: AdDeleteRequest): Promise<AdResult> {
    try {
      const result = await this.zone.runOutsideAngular(() => req.session.delete(req.dn, req.controls));
      return this.toAdResult(result);
    } catch (error) {
      throw normalizeError(error);
    }
  }

  async modifyEntry(req: AdModifyRequest): Promise<AdResult> {
    try {
      const result = await this.zone.runOutsideAngular(() => req.session.modify(req.dn, req.modifies, req.controls));
      return this.toAdResult(result);
    } catch (error) {
      throw normalizeError(error);
    }
  }

  async modifyDnEntry(req: AdModifyDnRequest): Promise<AdResult> {
    try {
      const result = await this.zone.runOutsideAngular(() =>
        req.session.modifyDn(req.dn, req.newRdn, req.deleteOldRdn, req.newSuperior ?? null, req.controls),
      );
      return this.toAdResult(result);
    } catch (error) {
      throw normalizeError(error);
    }
  }

  async initializeWasm(): Promise<void> {
    if (this.wasmInitialized) {
      return;
    }

    if (!this.wasmInitPromise) {
      this.wasmInitPromise = (async () => {
        await this.zone.runOutsideAngular(() => init());
        set_logging_level(LoggingLevel.Warn);
        this.wasmInitialized = true;
      })();
    }

    return this.wasmInitPromise;
  }

  private extractSearchEntries(messages: { op: { search_entry?: SearchEntryLike } }[]): SearchEntryLike[] {
    return messages.flatMap((message) => (message.op.search_entry ? [message.op.search_entry] : []));
  }

  private toSearchParameters(args: {
    search_base: string;
    filter: string;
    scope: SearchParameters['scope'];
    attributes: string[];
    size_limit?: number;
    time_limit?: number;
    controls?: LdapControlArrayLike;
  }): SearchParameters {
    return {
      search_base: args.search_base,
      filter: args.filter,
      scope: args.scope,
      attributes: args.attributes,
      size_limit: args.size_limit,
      time_limit: args.time_limit,
      controls: this.toLdapControls(args.controls),
    };
  }

  private toLdapControls(controls?: LdapControlArrayLike | null): LdapControlArray | undefined {
    return controls?.map((control) => this.toLdapControl(control));
  }

  private toLdapControl(control: LdapControlArrayLike[number]): LdapControl {
    if (this.isSimplePagedResultsControl(control)) {
      return {
        simple_paged_results: {
          size: control.simple_paged_results.size,
          cookie: control.simple_paged_results.cookie,
        },
      };
    }

    return control as LdapControl;
  }

  private isSimplePagedResultsControl(
    control: LdapControlArrayLike[number],
  ): control is { simple_paged_results: { size: number; cookie: number[] } } {
    return (
      'simple_paged_results' in control &&
      typeof control.simple_paged_results === 'object' &&
      control.simple_paged_results !== null &&
      'size' in control.simple_paged_results &&
      typeof control.simple_paged_results.size === 'number' &&
      'cookie' in control.simple_paged_results &&
      Array.isArray(control.simple_paged_results.cookie)
    );
  }

  private toSaslBindConfig(args: Parameters<LdapSessionLike['sasl_bind']>[0]): SaslBindConfig {
    return {
      username: args.username,
      password: args.password,
      auth_method: this.toSspiAuthMethod(args.auth_method),
      sign: args.sign,
      seal: args.seal,
      controls: this.toLdapControls(args.controls),
    };
  }

  private toBinaryLdapModifies(modifies: Parameters<LdapSessionLike['modify']>[1]): BinaryLdapModifies {
    return modifies.map(
      (modify): ModifyRequest => ({
        operation: modify.operation,
        attribute: this.toLdapAttribute(modify.attribute),
      }),
    );
  }

  private toAttributesArray(attributes: Parameters<LdapSessionLike['add']>[1]): AttributesArray {
    return attributes.map((attribute) => this.toLdapAttribute(attribute));
  }

  private toLdapAttribute(attribute: Parameters<LdapSessionLike['add']>[1][number]): Attribute {
    return {
      attribute_name: attribute.attribute_name,
      attribute_value: attribute.attribute_value,
    };
  }

  private toSspiAuthMethod(authMethod: unknown): SspiAuthMethod {
    if (this.isSspiAuthMethod(authMethod)) {
      return authMethod;
    }

    throw new Error('invalid active directory authentication method');
  }

  private isSspiAuthMethod(authMethod: unknown): authMethod is SspiAuthMethod {
    if (typeof authMethod !== 'object' || authMethod === null) {
      return false;
    }

    return 'negotiate' in authMethod || 'kerberos' in authMethod || 'ntlm' in authMethod;
  }

  private toAdResult(result: LdapResultLike | LdapResult): AdResult {
    return {
      code: String(result.code),
      message: result.message,
      matchedDn: this.getMatchedDn(result),
      referral: result.referral,
    };
  }

  private getMatchedDn(result: LdapResultLike | LdapResult): string | undefined {
    if ('matchedDn' in result && typeof result.matchedDn === 'string') {
      return result.matchedDn;
    }

    if ('matcheddn' in result && typeof result.matcheddn === 'string') {
      return result.matcheddn;
    }

    return undefined;
  }

  private resolveDomainAndServerComputerName(
    domain: string | undefined,
    serverComputerName: string,
  ): { domain: string | undefined; serverComputerName: string } {
    if (domain) {
      return {
        domain,
        serverComputerName: `${serverComputerName.replace(`.${domain}`, '')}.${domain}`,
      };
    }

    const parts = serverComputerName.split('.');

    return {
      domain: parts.length > 1 ? parts.slice(1).join('.') : undefined,
      serverComputerName,
    };
  }
}
