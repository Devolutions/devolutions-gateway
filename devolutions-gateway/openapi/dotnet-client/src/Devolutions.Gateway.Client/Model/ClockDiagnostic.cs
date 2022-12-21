/*
 * devolutions-gateway
 *
 * Protocol-aware fine-grained relay server
 *
 * The version of the OpenAPI document: 2022.3.3
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
    /// ClockDiagnostic
    /// </summary>
    [DataContract(Name = "ClockDiagnostic")]
    public partial class ClockDiagnostic : IEquatable<ClockDiagnostic>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ClockDiagnostic" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected ClockDiagnostic() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="ClockDiagnostic" /> class.
        /// </summary>
        /// <param name="timestampMillis">Current time in milliseconds (required).</param>
        /// <param name="timestampSecs">Current time in seconds (required).</param>
        public ClockDiagnostic(long timestampMillis = default(long), long timestampSecs = default(long))
        {
            this.TimestampMillis = timestampMillis;
            this.TimestampSecs = timestampSecs;
        }

        /// <summary>
        /// Current time in milliseconds
        /// </summary>
        /// <value>Current time in milliseconds</value>
        [DataMember(Name = "timestamp_millis", IsRequired = true, EmitDefaultValue = false)]
        public long TimestampMillis { get; set; }

        /// <summary>
        /// Current time in seconds
        /// </summary>
        /// <value>Current time in seconds</value>
        [DataMember(Name = "timestamp_secs", IsRequired = true, EmitDefaultValue = false)]
        public long TimestampSecs { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ClockDiagnostic {\n");
            sb.Append("  TimestampMillis: ").Append(TimestampMillis).Append("\n");
            sb.Append("  TimestampSecs: ").Append(TimestampSecs).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public virtual string ToJson()
        {
            return Newtonsoft.Json.JsonConvert.SerializeObject(this, Newtonsoft.Json.Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="input">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object input)
        {
            return this.Equals(input as ClockDiagnostic);
        }

        /// <summary>
        /// Returns true if ClockDiagnostic instances are equal
        /// </summary>
        /// <param name="input">Instance of ClockDiagnostic to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ClockDiagnostic input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.TimestampMillis == input.TimestampMillis ||
                    this.TimestampMillis.Equals(input.TimestampMillis)
                ) && 
                (
                    this.TimestampSecs == input.TimestampSecs ||
                    this.TimestampSecs.Equals(input.TimestampSecs)
                );
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                int hashCode = 41;
                hashCode = (hashCode * 59) + this.TimestampMillis.GetHashCode();
                hashCode = (hashCode * 59) + this.TimestampSecs.GetHashCode();
                return hashCode;
            }
        }

        /// <summary>
        /// To validate all properties of the instance
        /// </summary>
        /// <param name="validationContext">Validation context</param>
        /// <returns>Validation Result</returns>
        public IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> Validate(ValidationContext validationContext)
        {
            yield break;
        }
    }

}
