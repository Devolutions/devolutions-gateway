/*
 * Devolutions PEDM API
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
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
using FileParameter = Devolutions.Pedm.Client.Client.FileParameter;
using OpenAPIDateConverter = Devolutions.Pedm.Client.Client.OpenAPIDateConverter;

namespace Devolutions.Pedm.Client.Model
{
    /// <summary>
    /// Defines ElevationKind
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum ElevationKind
    {
        /// <summary>
        /// Enum AutoApprove for value: AutoApprove
        /// </summary>
        [EnumMember(Value = "AutoApprove")]
        AutoApprove = 1,

        /// <summary>
        /// Enum Confirm for value: Confirm
        /// </summary>
        [EnumMember(Value = "Confirm")]
        Confirm = 2,

        /// <summary>
        /// Enum ReasonApproval for value: ReasonApproval
        /// </summary>
        [EnumMember(Value = "ReasonApproval")]
        ReasonApproval = 3,

        /// <summary>
        /// Enum Deny for value: Deny
        /// </summary>
        [EnumMember(Value = "Deny")]
        Deny = 4
    }

}
