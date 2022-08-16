//----------------------
// <auto-generated>
//     Generated using the NSwag toolchain v13.16.1.0 (NJsonSchema v10.7.2.0 (Newtonsoft.Json v13.0.0.0)) (http://NSwag.org)
// </auto-generated>
//----------------------

/* tslint:disable */
/* eslint-disable */
// ReSharper disable InconsistentNaming

import { mergeMap as _observableMergeMap, catchError as _observableCatch } from 'rxjs/operators';
import { Observable, throwError as _observableThrow, of as _observableOf } from 'rxjs';
import { Injectable, Inject, Optional, InjectionToken } from '@angular/core';
import { HttpClient, HttpHeaders, HttpResponse, HttpResponseBase } from '@angular/common/http';

export const API_BASE_URL = new InjectionToken<string>('API_BASE_URL');

@Injectable({
    providedIn: 'root'
})
export class Client {
    private http: HttpClient;
    private baseUrl: string;
    protected jsonParseReviver: ((key: string, value: any) => any) | undefined = undefined;

    constructor(@Inject(HttpClient) http: HttpClient, @Optional() @Inject(API_BASE_URL) baseUrl?: string) {
        this.http = http;
        this.baseUrl = baseUrl !== undefined && baseUrl !== null ? baseUrl : "";
    }

    /**
     * Modifies configuration
     * @param body Partial JSON-encoded configuration
     * @return Configuration has been patched with success
     */
    patchConfig(body: string): Observable<void> {
        let url_ = this.baseUrl + "/jet/config";
        url_ = url_.replace(/[?&]$/, "");

        const content_ = JSON.stringify(body);

        let options_ : any = {
            body: content_,
            observe: "response",
            responseType: "blob",
            headers: new HttpHeaders({
                "Content-Type": "application/json",
            })
        };

        return this.http.request("patch", url_, options_).pipe(_observableMergeMap((response_ : any) => {
            return this.processPatchConfig(response_);
        })).pipe(_observableCatch((response_: any) => {
            if (response_ instanceof HttpResponseBase) {
                try {
                    return this.processPatchConfig(response_ as any);
                } catch (e) {
                    return _observableThrow(e) as any as Observable<void>;
                }
            } else
                return _observableThrow(response_) as any as Observable<void>;
        }));
    }

    protected processPatchConfig(response: HttpResponseBase): Observable<void> {
        const status = response.status;
        const responseBlob =
            response instanceof HttpResponse ? response.body :
            (response as any).error instanceof Blob ? (response as any).error : undefined;

        let _headers: any = {}; if (response.headers) { for (let key of response.headers.keys()) { _headers[key] = response.headers.get(key); }}
        if (status === 200) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return _observableOf<void>(null as any);
            }));
        } else if (status === 400) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("Bad patch request", status, _responseText, _headers);
            }));
        } else if (status === 401) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("Invalid or missing authorization token", status, _responseText, _headers);
            }));
        } else if (status === 403) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("Insufficient permissions", status, _responseText, _headers);
            }));
        } else if (status === 500) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("Failed to patch configuration", status, _responseText, _headers);
            }));
        } else if (status !== 200 && status !== 204) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("An unexpected server error occurred.", status, _responseText, _headers);
            }));
        }
        return _observableOf<void>(null as any);
    }

    /**
     * Retrieves server's clock in order to diagnose clock drifting.
     * @return Server's clock
     */
    getClock(): Observable<GatewayClock> {
        let url_ = this.baseUrl + "/jet/diagnostics/clock";
        url_ = url_.replace(/[?&]$/, "");

        let options_ : any = {
            observe: "response",
            responseType: "blob",
            headers: new HttpHeaders({
                "Accept": "application/json"
            })
        };

        return this.http.request("get", url_, options_).pipe(_observableMergeMap((response_ : any) => {
            return this.processGetClock(response_);
        })).pipe(_observableCatch((response_: any) => {
            if (response_ instanceof HttpResponseBase) {
                try {
                    return this.processGetClock(response_ as any);
                } catch (e) {
                    return _observableThrow(e) as any as Observable<GatewayClock>;
                }
            } else
                return _observableThrow(response_) as any as Observable<GatewayClock>;
        }));
    }

    protected processGetClock(response: HttpResponseBase): Observable<GatewayClock> {
        const status = response.status;
        const responseBlob =
            response instanceof HttpResponse ? response.body :
            (response as any).error instanceof Blob ? (response as any).error : undefined;

        let _headers: any = {}; if (response.headers) { for (let key of response.headers.keys()) { _headers[key] = response.headers.get(key); }}
        if (status === 200) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            let result200: any = null;
            let resultData200 = _responseText === "" ? null : JSON.parse(_responseText, this.jsonParseReviver);
            result200 = GatewayClock.fromJS(resultData200);
            return _observableOf(result200);
            }));
        } else if (status !== 200 && status !== 204) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("An unexpected server error occurred.", status, _responseText, _headers);
            }));
        }
        return _observableOf<GatewayClock>(null as any);
    }

    /**
     * Retrieves configuration.
     * @return Service configuration
     */
    getConfiguration(): Observable<GatewayConfiguration> {
        let url_ = this.baseUrl + "/jet/diagnostics/configuration";
        url_ = url_.replace(/[?&]$/, "");

        let options_ : any = {
            observe: "response",
            responseType: "blob",
            headers: new HttpHeaders({
                "Accept": "application/json"
            })
        };

        return this.http.request("get", url_, options_).pipe(_observableMergeMap((response_ : any) => {
            return this.processGetConfiguration(response_);
        })).pipe(_observableCatch((response_: any) => {
            if (response_ instanceof HttpResponseBase) {
                try {
                    return this.processGetConfiguration(response_ as any);
                } catch (e) {
                    return _observableThrow(e) as any as Observable<GatewayConfiguration>;
                }
            } else
                return _observableThrow(response_) as any as Observable<GatewayConfiguration>;
        }));
    }

    protected processGetConfiguration(response: HttpResponseBase): Observable<GatewayConfiguration> {
        const status = response.status;
        const responseBlob =
            response instanceof HttpResponse ? response.body :
            (response as any).error instanceof Blob ? (response as any).error : undefined;

        let _headers: any = {}; if (response.headers) { for (let key of response.headers.keys()) { _headers[key] = response.headers.get(key); }}
        if (status === 200) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            let result200: any = null;
            let resultData200 = _responseText === "" ? null : JSON.parse(_responseText, this.jsonParseReviver);
            result200 = GatewayConfiguration.fromJS(resultData200);
            return _observableOf(result200);
            }));
        } else if (status === 400) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("Bad request", status, _responseText, _headers);
            }));
        } else if (status === 401) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("Invalid or missing authorization token", status, _responseText, _headers);
            }));
        } else if (status === 403) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("Insufficient permissions", status, _responseText, _headers);
            }));
        } else if (status !== 200 && status !== 204) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("An unexpected server error occurred.", status, _responseText, _headers);
            }));
        }
        return _observableOf<GatewayConfiguration>(null as any);
    }

    /**
     * Retrieves latest logs.
     * @return Latest logs
     */
    getLogs(): Observable<string> {
        let url_ = this.baseUrl + "/jet/diagnostics/logs";
        url_ = url_.replace(/[?&]$/, "");

        let options_ : any = {
            observe: "response",
            responseType: "blob",
            headers: new HttpHeaders({
                "Accept": "text/plain"
            })
        };

        return this.http.request("get", url_, options_).pipe(_observableMergeMap((response_ : any) => {
            return this.processGetLogs(response_);
        })).pipe(_observableCatch((response_: any) => {
            if (response_ instanceof HttpResponseBase) {
                try {
                    return this.processGetLogs(response_ as any);
                } catch (e) {
                    return _observableThrow(e) as any as Observable<string>;
                }
            } else
                return _observableThrow(response_) as any as Observable<string>;
        }));
    }

    protected processGetLogs(response: HttpResponseBase): Observable<string> {
        const status = response.status;
        const responseBlob =
            response instanceof HttpResponse ? response.body :
            (response as any).error instanceof Blob ? (response as any).error : undefined;

        let _headers: any = {}; if (response.headers) { for (let key of response.headers.keys()) { _headers[key] = response.headers.get(key); }}
        if (status === 200) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            let result200: any = null;
            let resultData200 = _responseText === "" ? null : _responseText;
                result200 = resultData200 !== undefined ? resultData200 : <any>null;
    
            return _observableOf(result200);
            }));
        } else if (status === 400) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("Bad request", status, _responseText, _headers);
            }));
        } else if (status === 401) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("Invalid or missing authorization token", status, _responseText, _headers);
            }));
        } else if (status === 403) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("Insufficient permissions", status, _responseText, _headers);
            }));
        } else if (status === 500) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("Failed to retrieve logs", status, _responseText, _headers);
            }));
        } else if (status !== 200 && status !== 204) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("An unexpected server error occurred.", status, _responseText, _headers);
            }));
        }
        return _observableOf<string>(null as any);
    }

    /**
     * Performs a health check
     * @return Healthy message
     */
    getHealth(): Observable<string> {
        let url_ = this.baseUrl + "/jet/health";
        url_ = url_.replace(/[?&]$/, "");

        let options_ : any = {
            observe: "response",
            responseType: "blob",
            headers: new HttpHeaders({
                "Accept": "text/plain"
            })
        };

        return this.http.request("get", url_, options_).pipe(_observableMergeMap((response_ : any) => {
            return this.processGetHealth(response_);
        })).pipe(_observableCatch((response_: any) => {
            if (response_ instanceof HttpResponseBase) {
                try {
                    return this.processGetHealth(response_ as any);
                } catch (e) {
                    return _observableThrow(e) as any as Observable<string>;
                }
            } else
                return _observableThrow(response_) as any as Observable<string>;
        }));
    }

    protected processGetHealth(response: HttpResponseBase): Observable<string> {
        const status = response.status;
        const responseBlob =
            response instanceof HttpResponse ? response.body :
            (response as any).error instanceof Blob ? (response as any).error : undefined;

        let _headers: any = {}; if (response.headers) { for (let key of response.headers.keys()) { _headers[key] = response.headers.get(key); }}
        if (status === 200) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            let result200: any = null;
            let resultData200 = _responseText === "" ? null : _responseText;
                result200 = resultData200 !== undefined ? resultData200 : <any>null;
    
            return _observableOf(result200);
            }));
        } else if (status !== 200 && status !== 204) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("An unexpected server error occurred.", status, _responseText, _headers);
            }));
        }
        return _observableOf<string>(null as any);
    }

    /**
     * Lists running sessions
     * @return Running sessions
     */
    getSessions(): Observable<SessionInfo[]> {
        let url_ = this.baseUrl + "/jet/sessions";
        url_ = url_.replace(/[?&]$/, "");

        let options_ : any = {
            observe: "response",
            responseType: "blob",
            headers: new HttpHeaders({
                "Accept": "application/json"
            })
        };

        return this.http.request("get", url_, options_).pipe(_observableMergeMap((response_ : any) => {
            return this.processGetSessions(response_);
        })).pipe(_observableCatch((response_: any) => {
            if (response_ instanceof HttpResponseBase) {
                try {
                    return this.processGetSessions(response_ as any);
                } catch (e) {
                    return _observableThrow(e) as any as Observable<SessionInfo[]>;
                }
            } else
                return _observableThrow(response_) as any as Observable<SessionInfo[]>;
        }));
    }

    protected processGetSessions(response: HttpResponseBase): Observable<SessionInfo[]> {
        const status = response.status;
        const responseBlob =
            response instanceof HttpResponse ? response.body :
            (response as any).error instanceof Blob ? (response as any).error : undefined;

        let _headers: any = {}; if (response.headers) { for (let key of response.headers.keys()) { _headers[key] = response.headers.get(key); }}
        if (status === 200) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            let result200: any = null;
            let resultData200 = _responseText === "" ? null : JSON.parse(_responseText, this.jsonParseReviver);
            if (Array.isArray(resultData200)) {
                result200 = [] as any;
                for (let item of resultData200)
                    result200!.push(SessionInfo.fromJS(item));
            }
            else {
                result200 = <any>null;
            }
            return _observableOf(result200);
            }));
        } else if (status === 400) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("Bad request", status, _responseText, _headers);
            }));
        } else if (status === 401) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("Invalid or missing authorization token", status, _responseText, _headers);
            }));
        } else if (status === 403) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("Insufficient permissions", status, _responseText, _headers);
            }));
        } else if (status !== 200 && status !== 204) {
            return blobToText(responseBlob).pipe(_observableMergeMap(_responseText => {
            return throwException("An unexpected server error occurred.", status, _responseText, _headers);
            }));
        }
        return _observableOf<SessionInfo[]>(null as any);
    }
}

export enum ConnectionMode {
    Rdv = "rdv",
    Fwd = "fwd",
}

export class GatewayClock implements IGatewayClock {
    timestamp_millis!: number;
    timestamp_secs!: number;

    constructor(data?: IGatewayClock) {
        if (data) {
            for (var property in data) {
                if (data.hasOwnProperty(property))
                    (<any>this)[property] = (<any>data)[property];
            }
        }
    }

    init(_data?: any) {
        if (_data) {
            this.timestamp_millis = _data["timestamp_millis"];
            this.timestamp_secs = _data["timestamp_secs"];
        }
    }

    static fromJS(data: any): GatewayClock {
        data = typeof data === 'object' ? data : {};
        let result = new GatewayClock();
        result.init(data);
        return result;
    }

    toJSON(data?: any) {
        data = typeof data === 'object' ? data : {};
        data["timestamp_millis"] = this.timestamp_millis;
        data["timestamp_secs"] = this.timestamp_secs;
        return data;
    }

    clone(): GatewayClock {
        const json = this.toJSON();
        let result = new GatewayClock();
        result.init(json);
        return result;
    }
}

export interface IGatewayClock {
    timestamp_millis: number;
    timestamp_secs: number;
}

export class GatewayConfiguration implements IGatewayConfiguration {
    hostname!: string;
    id?: string;
    listeners!: ListenerUrls[];
    version!: string;

    constructor(data?: IGatewayConfiguration) {
        if (data) {
            for (var property in data) {
                if (data.hasOwnProperty(property))
                    (<any>this)[property] = (<any>data)[property];
            }
            if (data.listeners) {
                this.listeners = [];
                for (let i = 0; i < data.listeners.length; i++) {
                    let item = data.listeners[i];
                    this.listeners[i] = item && !(<any>item).toJSON ? new ListenerUrls(item) : <ListenerUrls>item;
                }
            }
        }
        if (!data) {
            this.listeners = [];
        }
    }

    init(_data?: any) {
        if (_data) {
            this.hostname = _data["hostname"];
            this.id = _data["id"];
            if (Array.isArray(_data["listeners"])) {
                this.listeners = [] as any;
                for (let item of _data["listeners"])
                    this.listeners!.push(ListenerUrls.fromJS(item));
            }
            this.version = _data["version"];
        }
    }

    static fromJS(data: any): GatewayConfiguration {
        data = typeof data === 'object' ? data : {};
        let result = new GatewayConfiguration();
        result.init(data);
        return result;
    }

    toJSON(data?: any) {
        data = typeof data === 'object' ? data : {};
        data["hostname"] = this.hostname;
        data["id"] = this.id;
        if (Array.isArray(this.listeners)) {
            data["listeners"] = [];
            for (let item of this.listeners)
                data["listeners"].push(item.toJSON());
        }
        data["version"] = this.version;
        return data;
    }

    clone(): GatewayConfiguration {
        const json = this.toJSON();
        let result = new GatewayConfiguration();
        result.init(json);
        return result;
    }
}

export interface IGatewayConfiguration {
    hostname: string;
    id?: string;
    listeners: IListenerUrls[];
    version: string;
}

export class ListenerUrls implements IListenerUrls {
    external_url!: string;
    internal_url!: string;

    constructor(data?: IListenerUrls) {
        if (data) {
            for (var property in data) {
                if (data.hasOwnProperty(property))
                    (<any>this)[property] = (<any>data)[property];
            }
        }
    }

    init(_data?: any) {
        if (_data) {
            this.external_url = _data["external_url"];
            this.internal_url = _data["internal_url"];
        }
    }

    static fromJS(data: any): ListenerUrls {
        data = typeof data === 'object' ? data : {};
        let result = new ListenerUrls();
        result.init(data);
        return result;
    }

    toJSON(data?: any) {
        data = typeof data === 'object' ? data : {};
        data["external_url"] = this.external_url;
        data["internal_url"] = this.internal_url;
        return data;
    }

    clone(): ListenerUrls {
        const json = this.toJSON();
        let result = new ListenerUrls();
        result.init(json);
        return result;
    }
}

export interface IListenerUrls {
    external_url: string;
    internal_url: string;
}

export class SessionInfo implements ISessionInfo {
    application_protocol!: string;
    association_id!: string;
    connection_mode!: ConnectionMode;
    destination_host?: string;
    filtering_policy!: boolean;
    recording_policy!: boolean;
    start_timestamp!: Date;

    constructor(data?: ISessionInfo) {
        if (data) {
            for (var property in data) {
                if (data.hasOwnProperty(property))
                    (<any>this)[property] = (<any>data)[property];
            }
        }
    }

    init(_data?: any) {
        if (_data) {
            this.application_protocol = _data["application_protocol"];
            this.association_id = _data["association_id"];
            this.connection_mode = _data["connection_mode"];
            this.destination_host = _data["destination_host"];
            this.filtering_policy = _data["filtering_policy"];
            this.recording_policy = _data["recording_policy"];
            this.start_timestamp = _data["start_timestamp"] ? new Date(_data["start_timestamp"].toString()) : <any>undefined;
        }
    }

    static fromJS(data: any): SessionInfo {
        data = typeof data === 'object' ? data : {};
        let result = new SessionInfo();
        result.init(data);
        return result;
    }

    toJSON(data?: any) {
        data = typeof data === 'object' ? data : {};
        data["application_protocol"] = this.application_protocol;
        data["association_id"] = this.association_id;
        data["connection_mode"] = this.connection_mode;
        data["destination_host"] = this.destination_host;
        data["filtering_policy"] = this.filtering_policy;
        data["recording_policy"] = this.recording_policy;
        data["start_timestamp"] = this.start_timestamp ? this.start_timestamp.toISOString() : <any>undefined;
        return data;
    }

    clone(): SessionInfo {
        const json = this.toJSON();
        let result = new SessionInfo();
        result.init(json);
        return result;
    }
}

export interface ISessionInfo {
    application_protocol: string;
    association_id: string;
    connection_mode: ConnectionMode;
    destination_host?: string;
    filtering_policy: boolean;
    recording_policy: boolean;
    start_timestamp: Date;
}

export class ApiException extends Error {
    message: string;
    status: number;
    response: string;
    headers: { [key: string]: any; };
    result: any;

    constructor(message: string, status: number, response: string, headers: { [key: string]: any; }, result: any) {
        super();

        this.message = message;
        this.status = status;
        this.response = response;
        this.headers = headers;
        this.result = result;
    }

    protected isApiException = true;

    static isApiException(obj: any): obj is ApiException {
        return obj.isApiException === true;
    }
}

function throwException(message: string, status: number, response: string, headers: { [key: string]: any; }, result?: any): Observable<any> {
    if (result !== null && result !== undefined)
        return _observableThrow(result);
    else
        return _observableThrow(new ApiException(message, status, response, headers, null));
}

function blobToText(blob: any): Observable<string> {
    return new Observable<string>((observer: any) => {
        if (!blob) {
            observer.next("");
            observer.complete();
        } else {
            let reader = new FileReader();
            reader.onload = event => {
                observer.next((event.target as any).result);
                observer.complete();
            };
            reader.readAsText(blob);
        }
    });
}