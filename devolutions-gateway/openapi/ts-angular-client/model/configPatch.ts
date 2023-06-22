/**
 * devolutions-gateway
 * Protocol-aware fine-grained relay server
 *
 * The version of the OpenAPI document: 2023.2.1
 * Contact: infos@devolutions.net
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
import { Subscriber } from './subscriber';
import { SubProvisionerKey } from './subProvisionerKey';


export interface ConfigPatch { 
    /**
     * This Gateway\'s unique ID
     */
    Id?: string | null;
    SubProvisionerPublicKey?: SubProvisionerKey | null;
    Subscriber?: Subscriber | null;
}

