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
    /// Defines AuthenticodeSignatureStatus
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum AuthenticodeSignatureStatus
    {
        /// <summary>
        /// Enum Valid for value: Valid
        /// </summary>
        [EnumMember(Value = "Valid")]
        Valid = 1,

        /// <summary>
        /// Enum Incompatible for value: Incompatible
        /// </summary>
        [EnumMember(Value = "Incompatible")]
        Incompatible = 2,

        /// <summary>
        /// Enum NotSigned for value: NotSigned
        /// </summary>
        [EnumMember(Value = "NotSigned")]
        NotSigned = 3,

        /// <summary>
        /// Enum HashMismatch for value: HashMismatch
        /// </summary>
        [EnumMember(Value = "HashMismatch")]
        HashMismatch = 4,

        /// <summary>
        /// Enum NotSupportedFileFormat for value: NotSupportedFileFormat
        /// </summary>
        [EnumMember(Value = "NotSupportedFileFormat")]
        NotSupportedFileFormat = 5,

        /// <summary>
        /// Enum NotTrusted for value: NotTrusted
        /// </summary>
        [EnumMember(Value = "NotTrusted")]
        NotTrusted = 6
    }

    public static class AuthenticodeSignatureStatusExtensions
    {
        /// <summary>
        /// Returns the value as string for a given variant
        /// </summary>
        public static string ToValue(this AuthenticodeSignatureStatus variant)
        {
            switch (variant)
            {
                case AuthenticodeSignatureStatus.Valid:
                    return "Valid";
                case AuthenticodeSignatureStatus.Incompatible:
                    return "Incompatible";
                case AuthenticodeSignatureStatus.NotSigned:
                    return "NotSigned";
                case AuthenticodeSignatureStatus.HashMismatch:
                    return "HashMismatch";
                case AuthenticodeSignatureStatus.NotSupportedFileFormat:
                    return "NotSupportedFileFormat";
                case AuthenticodeSignatureStatus.NotTrusted:
                    return "NotTrusted";
                default:
                    throw new ArgumentOutOfRangeException(nameof(variant), $"Unexpected variant: {variant}");
            }
        }
    }

}
