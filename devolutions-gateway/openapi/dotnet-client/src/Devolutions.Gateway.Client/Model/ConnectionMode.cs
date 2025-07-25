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

    public static class ConnectionModeExtensions
    {
        /// <summary>
        /// Returns the value as string for a given variant
        /// </summary>
        public static string ToValue(this ConnectionMode variant)
        {
            switch (variant)
            {
                case ConnectionMode.Rdv:
                    return "rdv";
                case ConnectionMode.Fwd:
                    return "fwd";
                default:
                    throw new ArgumentOutOfRangeException(nameof(variant), $"Unexpected variant: {variant}");
            }
        }
    }

}
