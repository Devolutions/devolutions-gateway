/*
 * devolutions-gateway
 *
 * Protocol-aware fine-grained relay server
 *
 * The version of the OpenAPI document: 2023.3.0
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
    /// ListenerUrls
    /// </summary>
    [DataContract(Name = "ListenerUrls")]
    public partial class ListenerUrls : IEquatable<ListenerUrls>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ListenerUrls" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected ListenerUrls() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="ListenerUrls" /> class.
        /// </summary>
        /// <param name="externalUrl">URL to use from external networks (required).</param>
        /// <param name="internalUrl">URL to use on local network (required).</param>
        public ListenerUrls(string externalUrl = default(string), string internalUrl = default(string))
        {
            // to ensure "externalUrl" is required (not null)
            if (externalUrl == null)
            {
                throw new ArgumentNullException("externalUrl is a required property for ListenerUrls and cannot be null");
            }
            this.ExternalUrl = externalUrl;
            // to ensure "internalUrl" is required (not null)
            if (internalUrl == null)
            {
                throw new ArgumentNullException("internalUrl is a required property for ListenerUrls and cannot be null");
            }
            this.InternalUrl = internalUrl;
        }

        /// <summary>
        /// URL to use from external networks
        /// </summary>
        /// <value>URL to use from external networks</value>
        [DataMember(Name = "external_url", IsRequired = true, EmitDefaultValue = true)]
        public string ExternalUrl { get; set; }

        /// <summary>
        /// URL to use on local network
        /// </summary>
        /// <value>URL to use on local network</value>
        [DataMember(Name = "internal_url", IsRequired = true, EmitDefaultValue = true)]
        public string InternalUrl { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ListenerUrls {\n");
            sb.Append("  ExternalUrl: ").Append(ExternalUrl).Append("\n");
            sb.Append("  InternalUrl: ").Append(InternalUrl).Append("\n");
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
            return this.Equals(input as ListenerUrls);
        }

        /// <summary>
        /// Returns true if ListenerUrls instances are equal
        /// </summary>
        /// <param name="input">Instance of ListenerUrls to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ListenerUrls input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.ExternalUrl == input.ExternalUrl ||
                    (this.ExternalUrl != null &&
                    this.ExternalUrl.Equals(input.ExternalUrl))
                ) && 
                (
                    this.InternalUrl == input.InternalUrl ||
                    (this.InternalUrl != null &&
                    this.InternalUrl.Equals(input.InternalUrl))
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
                if (this.ExternalUrl != null)
                {
                    hashCode = (hashCode * 59) + this.ExternalUrl.GetHashCode();
                }
                if (this.InternalUrl != null)
                {
                    hashCode = (hashCode * 59) + this.InternalUrl.GetHashCode();
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
