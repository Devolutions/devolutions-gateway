/*
 * devolutions-gateway
 *
 * Protocol-aware fine-grained relay server
 *
 * The version of the OpenAPI document: 2022.2.2
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
        GatewayConfigWrite = 7

    }

}
