/**
 * devolutions-gateway
 * Protocol-aware fine-grained relay server
 *
 * The version of the OpenAPI document: 2024.3.2
 * Contact: infos@devolutions.net
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


export interface Heartbeat { 
    /**
     * This Gateway\'s hostname
     */
    hostname: string;
    /**
     * This Gateway\'s unique ID
     */
    id?: string | null;
    /**
     * The remaining available space to store recordings, in bytes.  Since v2024.1.6.
     */
    recording_storage_available_space?: number | null;
    /**
     * Whether the recording storage is writeable or not.  Since v2024.1.6.
     */
    recording_storage_is_writeable?: boolean | null;
    /**
     * The total space of the disk used to store recordings, in bytes.  Since v2024.1.6.
     */
    recording_storage_total_space?: number | null;
    /**
     * Number of running sessions
     */
    running_session_count: number;
    /**
     * Gateway service version
     */
    version: string;
}

