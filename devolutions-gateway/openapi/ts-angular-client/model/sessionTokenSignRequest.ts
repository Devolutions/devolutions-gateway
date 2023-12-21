/**
 * devolutions-gateway
 * Protocol-aware fine-grained relay server
 *
 * The version of the OpenAPI document: 2023.3.0
 * Contact: infos@devolutions.net
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
import { SessionTokenContentType } from './sessionTokenContentType';


export interface SessionTokenSignRequest { 
    content_type: SessionTokenContentType;
    /**
     * Destination host
     */
    destination?: string | null;
    /**
     * Kerberos KDC address.  E.g.: `tcp://IT-HELP-DC.ad.it-help.ninja:88`. Default scheme is `tcp`. Default port is `88`.
     */
    krb_kdc?: string | null;
    /**
     * Kerberos realm.  E.g.: `ad.it-help.ninja`. Should be lowercased (actual validation is case-insensitive though).
     */
    krb_realm?: string | null;
    /**
     * The validity duration in seconds for the session token.  This value cannot exceed 2 hours.
     */
    lifetime: number;
    /**
     * Protocol for the session (e.g.: \"rdp\")
     */
    protocol?: string | null;
    /**
     * Unique ID for this session
     */
    session_id?: string | null;
}
export namespace SessionTokenSignRequest {
}


