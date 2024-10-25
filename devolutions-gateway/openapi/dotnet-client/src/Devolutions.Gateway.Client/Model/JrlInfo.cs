/*
 * devolutions-gateway
 *
 * Protocol-aware fine-grained relay server
 *
 * The version of the OpenAPI document: 2024.3.6
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
    /// JrlInfo
    /// </summary>
    [DataContract(Name = "JrlInfo")]
    public partial class JrlInfo : IValidatableObject
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
        /// To validate all properties of the instance
        /// </summary>
        /// <param name="validationContext">Validation context</param>
        /// <returns>Validation Result</returns>
        IEnumerable<ValidationResult> IValidatableObject.Validate(ValidationContext validationContext)
        {
            yield break;
        }
    }

}
