/*
 * devolutions-gateway
 *
 * Protocol-aware fine-grained relay server
 *
 * The version of the OpenAPI document: 2025.2.2
 * Contact: infos@devolutions.net
 * Generated by: https://github.com/openapitools/openapi-generator.git
 */


using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System.ComponentModel.DataAnnotations;
using FileParameter = Devolutions.Gateway.Client.Client.FileParameter;
using OpenAPIDateConverter = Devolutions.Gateway.Client.Client.OpenAPIDateConverter;

namespace Devolutions.Gateway.Client.Model
{
    /// <summary>
    /// Defines AccessScope
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum AccessScope
    {
        /// <summary>
        /// Enum Star for value: *
        /// </summary>
        [EnumMember(Value = "*")]
        Star = 1,

        /// <summary>
        /// Enum GatewaySessionsRead for value: gateway.sessions.read
        /// </summary>
        [EnumMember(Value = "gateway.sessions.read")]
        GatewaySessionsRead = 2,

        /// <summary>
        /// Enum GatewaySessionTerminate for value: gateway.session.terminate
        /// </summary>
        [EnumMember(Value = "gateway.session.terminate")]
        GatewaySessionTerminate = 3,

        /// <summary>
        /// Enum GatewayAssociationsRead for value: gateway.associations.read
        /// </summary>
        [EnumMember(Value = "gateway.associations.read")]
        GatewayAssociationsRead = 4,

        /// <summary>
        /// Enum GatewayDiagnosticsRead for value: gateway.diagnostics.read
        /// </summary>
        [EnumMember(Value = "gateway.diagnostics.read")]
        GatewayDiagnosticsRead = 5,

        /// <summary>
        /// Enum GatewayJrlRead for value: gateway.jrl.read
        /// </summary>
        [EnumMember(Value = "gateway.jrl.read")]
        GatewayJrlRead = 6,

        /// <summary>
        /// Enum GatewayConfigWrite for value: gateway.config.write
        /// </summary>
        [EnumMember(Value = "gateway.config.write")]
        GatewayConfigWrite = 7,

        /// <summary>
        /// Enum GatewayHeartbeatRead for value: gateway.heartbeat.read
        /// </summary>
        [EnumMember(Value = "gateway.heartbeat.read")]
        GatewayHeartbeatRead = 8,

        /// <summary>
        /// Enum GatewayRecordingDelete for value: gateway.recording.delete
        /// </summary>
        [EnumMember(Value = "gateway.recording.delete")]
        GatewayRecordingDelete = 9,

        /// <summary>
        /// Enum GatewayRecordingsRead for value: gateway.recordings.read
        /// </summary>
        [EnumMember(Value = "gateway.recordings.read")]
        GatewayRecordingsRead = 10,

        /// <summary>
        /// Enum GatewayUpdate for value: gateway.update
        /// </summary>
        [EnumMember(Value = "gateway.update")]
        GatewayUpdate = 11,

        /// <summary>
        /// Enum GatewayPreflight for value: gateway.preflight
        /// </summary>
        [EnumMember(Value = "gateway.preflight")]
        GatewayPreflight = 12
    }

    public static class AccessScopeExtensions
    {
        /// <summary>
        /// Returns the value as string for a given variant
        /// </summary>
        public static string ToValue(this AccessScope variant)
        {
            switch (variant)
            {
                case AccessScope.Star:
                    return "*";
                case AccessScope.GatewaySessionsRead:
                    return "gateway.sessions.read";
                case AccessScope.GatewaySessionTerminate:
                    return "gateway.session.terminate";
                case AccessScope.GatewayAssociationsRead:
                    return "gateway.associations.read";
                case AccessScope.GatewayDiagnosticsRead:
                    return "gateway.diagnostics.read";
                case AccessScope.GatewayJrlRead:
                    return "gateway.jrl.read";
                case AccessScope.GatewayConfigWrite:
                    return "gateway.config.write";
                case AccessScope.GatewayHeartbeatRead:
                    return "gateway.heartbeat.read";
                case AccessScope.GatewayRecordingDelete:
                    return "gateway.recording.delete";
                case AccessScope.GatewayRecordingsRead:
                    return "gateway.recordings.read";
                case AccessScope.GatewayUpdate:
                    return "gateway.update";
                case AccessScope.GatewayPreflight:
                    return "gateway.preflight";
                default:
                    throw new ArgumentOutOfRangeException(nameof(variant), $"Unexpected variant: {variant}");
            }
        }
    }

}
