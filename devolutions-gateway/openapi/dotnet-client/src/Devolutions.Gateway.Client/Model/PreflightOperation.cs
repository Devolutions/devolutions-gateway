/*
 * devolutions-gateway
 *
 * Protocol-aware fine-grained relay server
 *
 * The version of the OpenAPI document: 2025.1.4
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
    /// PreflightOperation
    /// </summary>
    [DataContract(Name = "PreflightOperation")]
    public partial class PreflightOperation : IValidatableObject
    {

        /// <summary>
        /// Gets or Sets Kind
        /// </summary>
        [DataMember(Name = "kind", IsRequired = true, EmitDefaultValue = true)]
        public PreflightOperationKind Kind { get; set; }
        /// <summary>
        /// Initializes a new instance of the <see cref="PreflightOperation" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected PreflightOperation() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="PreflightOperation" /> class.
        /// </summary>
        /// <param name="associationId">A unique ID identifying the session for which the credentials should be used.  Required for \&quot;push-credentials\&quot; kind..</param>
        /// <param name="hostToLookup">The hostname to perform DNS lookup on.  Required for \&quot;lookup-host\&quot; kind..</param>
        /// <param name="id">Unique ID identifying the preflight operation. (required).</param>
        /// <param name="kind">kind (required).</param>
        /// <param name="proxyCredentials">proxyCredentials.</param>
        /// <param name="targetCredentials">targetCredentials.</param>
        /// <param name="token">The token to be pushed on the proxy-side.  Required for \&quot;push-token\&quot; kind..</param>
        public PreflightOperation(Guid? associationId = default(Guid?), string hostToLookup = default(string), Guid id = default(Guid), PreflightOperationKind kind = default(PreflightOperationKind), Credentials proxyCredentials = default(Credentials), Credentials targetCredentials = default(Credentials), string token = default(string))
        {
            this.Id = id;
            this.Kind = kind;
            this.AssociationId = associationId;
            this.HostToLookup = hostToLookup;
            this.ProxyCredentials = proxyCredentials;
            this.TargetCredentials = targetCredentials;
            this.Token = token;
        }

        /// <summary>
        /// A unique ID identifying the session for which the credentials should be used.  Required for \&quot;push-credentials\&quot; kind.
        /// </summary>
        /// <value>A unique ID identifying the session for which the credentials should be used.  Required for \&quot;push-credentials\&quot; kind.</value>
        [DataMember(Name = "association_id", EmitDefaultValue = true)]
        public Guid? AssociationId { get; set; }

        /// <summary>
        /// The hostname to perform DNS lookup on.  Required for \&quot;lookup-host\&quot; kind.
        /// </summary>
        /// <value>The hostname to perform DNS lookup on.  Required for \&quot;lookup-host\&quot; kind.</value>
        [DataMember(Name = "host_to_lookup", EmitDefaultValue = true)]
        public string HostToLookup { get; set; }

        /// <summary>
        /// Unique ID identifying the preflight operation.
        /// </summary>
        /// <value>Unique ID identifying the preflight operation.</value>
        [DataMember(Name = "id", IsRequired = true, EmitDefaultValue = true)]
        public Guid Id { get; set; }

        /// <summary>
        /// Gets or Sets ProxyCredentials
        /// </summary>
        [DataMember(Name = "proxy_credentials", EmitDefaultValue = true)]
        public Credentials ProxyCredentials { get; set; }

        /// <summary>
        /// Gets or Sets TargetCredentials
        /// </summary>
        [DataMember(Name = "target_credentials", EmitDefaultValue = true)]
        public Credentials TargetCredentials { get; set; }

        /// <summary>
        /// The token to be pushed on the proxy-side.  Required for \&quot;push-token\&quot; kind.
        /// </summary>
        /// <value>The token to be pushed on the proxy-side.  Required for \&quot;push-token\&quot; kind.</value>
        [DataMember(Name = "token", EmitDefaultValue = true)]
        public string Token { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class PreflightOperation {\n");
            sb.Append("  AssociationId: ").Append(AssociationId).Append("\n");
            sb.Append("  HostToLookup: ").Append(HostToLookup).Append("\n");
            sb.Append("  Id: ").Append(Id).Append("\n");
            sb.Append("  Kind: ").Append(Kind).Append("\n");
            sb.Append("  ProxyCredentials: ").Append(ProxyCredentials).Append("\n");
            sb.Append("  TargetCredentials: ").Append(TargetCredentials).Append("\n");
            sb.Append("  Token: ").Append(Token).Append("\n");
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
