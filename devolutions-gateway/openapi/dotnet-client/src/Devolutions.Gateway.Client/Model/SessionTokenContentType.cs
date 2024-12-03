/*
 * devolutions-gateway
 *
 * Protocol-aware fine-grained relay server
 *
 * The version of the OpenAPI document: 2024.3.5
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
    /// Defines SessionTokenContentType
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum SessionTokenContentType
    {
        /// <summary>
        /// Enum ASSOCIATION for value: ASSOCIATION
        /// </summary>
        [EnumMember(Value = "ASSOCIATION")]
        ASSOCIATION = 1,

        /// <summary>
        /// Enum JMUX for value: JMUX
        /// </summary>
        [EnumMember(Value = "JMUX")]
        JMUX = 2,

        /// <summary>
        /// Enum KDC for value: KDC
        /// </summary>
        [EnumMember(Value = "KDC")]
        KDC = 3
    }

    public static class SessionTokenContentTypeExtensions
    {
        /// <summary>
        /// Returns the value as string for a given variant
        /// </summary>
        public static string ToValue(this SessionTokenContentType variant)
        {
            switch (variant)
            {
                case SessionTokenContentType.ASSOCIATION:
                    return "ASSOCIATION";
                case SessionTokenContentType.JMUX:
                    return "JMUX";
                case SessionTokenContentType.KDC:
                    return "KDC";
                default:
                    throw new ArgumentOutOfRangeException(nameof(variant), $"Unexpected variant: {variant}");
            }
        }
    }

}
