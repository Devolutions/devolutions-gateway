/*
 * devolutions-gateway
 *
 * Protocol-aware fine-grained relay server
 *
 * The version of the OpenAPI document: 2023.1.1
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
    /// Identity
    /// </summary>
    [DataContract(Name = "Identity")]
    public partial class Identity : IEquatable<Identity>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Identity" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected Identity() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="Identity" /> class.
        /// </summary>
        /// <param name="hostname">This Gateway&#39;s hostname (required).</param>
        /// <param name="id">This Gateway&#39;s unique ID.</param>
        /// <param name="version">Gateway service version.</param>
        public Identity(string hostname = default(string), Guid id = default(Guid), string version = default(string))
        {
            // to ensure "hostname" is required (not null)
            if (hostname == null)
            {
                throw new ArgumentNullException("hostname is a required property for Identity and cannot be null");
            }
            this.Hostname = hostname;
            this.Id = id;
            this._Version = version;
        }

        /// <summary>
        /// This Gateway&#39;s hostname
        /// </summary>
        /// <value>This Gateway&#39;s hostname</value>
        [DataMember(Name = "hostname", IsRequired = true, EmitDefaultValue = false)]
        public string Hostname { get; set; }

        /// <summary>
        /// This Gateway&#39;s unique ID
        /// </summary>
        /// <value>This Gateway&#39;s unique ID</value>
        [DataMember(Name = "id", EmitDefaultValue = false)]
        public Guid Id { get; set; }

        /// <summary>
        /// Gateway service version
        /// </summary>
        /// <value>Gateway service version</value>
        [DataMember(Name = "version", EmitDefaultValue = false)]
        public string _Version { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class Identity {\n");
            sb.Append("  Hostname: ").Append(Hostname).Append("\n");
            sb.Append("  Id: ").Append(Id).Append("\n");
            sb.Append("  _Version: ").Append(_Version).Append("\n");
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
            return this.Equals(input as Identity);
        }

        /// <summary>
        /// Returns true if Identity instances are equal
        /// </summary>
        /// <param name="input">Instance of Identity to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(Identity input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Hostname == input.Hostname ||
                    (this.Hostname != null &&
                    this.Hostname.Equals(input.Hostname))
                ) && 
                (
                    this.Id == input.Id ||
                    (this.Id != null &&
                    this.Id.Equals(input.Id))
                ) && 
                (
                    this._Version == input._Version ||
                    (this._Version != null &&
                    this._Version.Equals(input._Version))
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
                if (this.Hostname != null)
                {
                    hashCode = (hashCode * 59) + this.Hostname.GetHashCode();
                }
                if (this.Id != null)
                {
                    hashCode = (hashCode * 59) + this.Id.GetHashCode();
                }
                if (this._Version != null)
                {
                    hashCode = (hashCode * 59) + this._Version.GetHashCode();
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
