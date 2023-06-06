/**
 * devolutions-gateway
 * Protocol-aware fine-grained relay server
 *
 * The version of the OpenAPI document: 2023.2.0
 * Contact: infos@devolutions.net
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


/**
 * Subscriber configuration
 */
export interface Subscriber { 
    /**
     * Bearer token to use when making HTTP requests
     */
    Token: string;
    /**
     * HTTP URL where notification messages are to be sent
     */
    Url: string;
}

