/**
 * devolutions-gateway
 *
 * Contact: infos@devolutions.net
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
import { PreflightOutputKind } from './preflightOutputKind';
import { PreflightAlertStatus } from './preflightAlertStatus';


export interface PreflightOutput { 
    /**
     * Agent service version, if installed.  Set for \"agent-version\" kind.
     */
    agent_version?: string | null;
    /**
     * Message describing the problem.  Set for \"alert\" kind.
     */
    alert_message?: string | null;
    alert_status?: PreflightAlertStatus | null;
    kind: PreflightOutputKind;
    /**
     * The ID of the preflight operation associated to this result.
     */
    operation_id: string;
    /**
     * The remaining available space to store recordings, in bytes.  set for \"recording-storage-health\" kind.
     */
    recording_storage_available_space?: number | null;
    /**
     * Whether the recording storage is writeable or not.  Set for \"recording-storage-health\" kind.
     */
    recording_storage_is_writeable?: boolean | null;
    /**
     * The total space of the disk used to store recordings, in bytes.  Set for \"recording-storage-health\" kind.
     */
    recording_storage_total_space?: number | null;
    /**
     * Resolved IP addresses.  Set for \"resolved-host\" kind.
     */
    resolved_addresses?: Array<string> | null;
    /**
     * Hostname that was resolved.  Set for \"resolved-host\" kind.
     */
    resolved_host?: string | null;
    /**
     * Number of running sessions.  Set for \"running-session-count\" kind.
     */
    running_session_count?: number | null;
    /**
     * Service version.  Set for \"version\" kind.
     */
    version?: string | null;
}
export namespace PreflightOutput {
}


