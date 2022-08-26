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
    /// Defines ConnectionMode
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum ConnectionMode
    {
        /// <summary>
        /// Enum Rdv for value: rdv
        /// </summary>
        [EnumMember(Value = "rdv")]
        Rdv = 1,

        /// <summary>
        /// Enum Fwd for value: fwd
        /// </summary>
        [EnumMember(Value = "fwd")]
        Fwd = 2

    }

}
