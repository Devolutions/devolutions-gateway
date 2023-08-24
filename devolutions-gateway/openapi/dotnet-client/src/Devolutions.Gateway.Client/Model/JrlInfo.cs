/*
 * devolutions-gateway
 *
 * Protocol-aware fine-grained relay server
 *
 * The version of the OpenAPI document: 2023.2.3
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
    /// JrlInfo
    /// </summary>
    [DataContract(Name = "JrlInfo")]
    public partial class JrlInfo : IEquatable<JrlInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="JrlInfo" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected JrlInfo() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="JrlInfo" /> class.
        /// </summary>
        /// <param name="iat">JWT \&quot;Issued At\&quot; claim of JRL (required).</param>
        /// <param name="jti">Unique ID for current JRL (required).</param>
        public JrlInfo(long iat = default(long), Guid jti = default(Guid))
        {
            this.Iat = iat;
            this.Jti = jti;
        }

        /// <summary>
        /// JWT \&quot;Issued At\&quot; claim of JRL
        /// </summary>
        /// <value>JWT \&quot;Issued At\&quot; claim of JRL</value>
        [DataMember(Name = "iat", IsRequired = true, EmitDefaultValue = true)]
        public long Iat { get; set; }

        /// <summary>
        /// Unique ID for current JRL
        /// </summary>
        /// <value>Unique ID for current JRL</value>
        [DataMember(Name = "jti", IsRequired = true, EmitDefaultValue = true)]
        public Guid Jti { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class JrlInfo {\n");
            sb.Append("  Iat: ").Append(Iat).Append("\n");
            sb.Append("  Jti: ").Append(Jti).Append("\n");
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
            return this.Equals(input as JrlInfo);
        }

        /// <summary>
        /// Returns true if JrlInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of JrlInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(JrlInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Iat == input.Iat ||
                    this.Iat.Equals(input.Iat)
                ) && 
                (
                    this.Jti == input.Jti ||
                    (this.Jti != null &&
                    this.Jti.Equals(input.Jti))
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
                hashCode = (hashCode * 59) + this.Iat.GetHashCode();
                if (this.Jti != null)
                {
                    hashCode = (hashCode * 59) + this.Jti.GetHashCode();
                }
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
