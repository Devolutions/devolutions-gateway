/*
 * devolutions-gateway
 *
 * Protocol-aware fine-grained relay server
 *
 * The version of the OpenAPI document: 2024.1.3
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
    /// Service configuration diagnostic
    /// </summary>
    [DataContract(Name = "ConfigDiagnostic")]
    public partial class ConfigDiagnostic : IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigDiagnostic" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected ConfigDiagnostic() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigDiagnostic" /> class.
        /// </summary>
        /// <param name="hostname">This Gateway&#39;s hostname (required).</param>
        /// <param name="id">This Gateway&#39;s unique ID.</param>
        /// <param name="listeners">Listeners configured on this instance (required).</param>
        /// <param name="varVersion">Gateway service version (required).</param>
        public ConfigDiagnostic(string hostname = default(string), Guid? id = default(Guid?), List<ListenerUrls> listeners = default(List<ListenerUrls>), string varVersion = default(string))
        {
            // to ensure "hostname" is required (not null)
            if (hostname == null)
            {
                throw new ArgumentNullException("hostname is a required property for ConfigDiagnostic and cannot be null");
            }
            this.Hostname = hostname;
            // to ensure "listeners" is required (not null)
            if (listeners == null)
            {
                throw new ArgumentNullException("listeners is a required property for ConfigDiagnostic and cannot be null");
            }
            this.Listeners = listeners;
            // to ensure "varVersion" is required (not null)
            if (varVersion == null)
            {
                throw new ArgumentNullException("varVersion is a required property for ConfigDiagnostic and cannot be null");
            }
            this.VarVersion = varVersion;
            this.Id = id;
        }

        /// <summary>
        /// This Gateway&#39;s hostname
        /// </summary>
        /// <value>This Gateway&#39;s hostname</value>
        [DataMember(Name = "hostname", IsRequired = true, EmitDefaultValue = true)]
        public string Hostname { get; set; }

        /// <summary>
        /// This Gateway&#39;s unique ID
        /// </summary>
        /// <value>This Gateway&#39;s unique ID</value>
        [DataMember(Name = "id", EmitDefaultValue = true)]
        public Guid? Id { get; set; }

        /// <summary>
        /// Listeners configured on this instance
        /// </summary>
        /// <value>Listeners configured on this instance</value>
        [DataMember(Name = "listeners", IsRequired = true, EmitDefaultValue = true)]
        public List<ListenerUrls> Listeners { get; set; }

        /// <summary>
        /// Gateway service version
        /// </summary>
        /// <value>Gateway service version</value>
        [DataMember(Name = "version", IsRequired = true, EmitDefaultValue = true)]
        public string VarVersion { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ConfigDiagnostic {\n");
            sb.Append("  Hostname: ").Append(Hostname).Append("\n");
            sb.Append("  Id: ").Append(Id).Append("\n");
            sb.Append("  Listeners: ").Append(Listeners).Append("\n");
            sb.Append("  VarVersion: ").Append(VarVersion).Append("\n");
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
        IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> IValidatableObject.Validate(ValidationContext validationContext)
        {
            yield break;
        }
    }

}
