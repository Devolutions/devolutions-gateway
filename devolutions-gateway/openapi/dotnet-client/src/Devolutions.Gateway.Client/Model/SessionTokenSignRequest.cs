/*
 * devolutions-gateway
 *
 * Protocol-aware fine-grained relay server
 *
 * The version of the OpenAPI document: 2024.1.5
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
    /// SessionTokenSignRequest
    /// </summary>
    [DataContract(Name = "SessionTokenSignRequest")]
    public partial class SessionTokenSignRequest : IValidatableObject
    {

        /// <summary>
        /// Gets or Sets ContentType
        /// </summary>
        [DataMember(Name = "content_type", IsRequired = true, EmitDefaultValue = true)]
        public SessionTokenContentType ContentType { get; set; }
        /// <summary>
        /// Initializes a new instance of the <see cref="SessionTokenSignRequest" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected SessionTokenSignRequest() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="SessionTokenSignRequest" /> class.
        /// </summary>
        /// <param name="contentType">contentType (required).</param>
        /// <param name="destination">Destination host.</param>
        /// <param name="krbKdc">Kerberos KDC address.  E.g.: &#x60;tcp://IT-HELP-DC.ad.it-help.ninja:88&#x60;. Default scheme is &#x60;tcp&#x60;. Default port is &#x60;88&#x60;..</param>
        /// <param name="krbRealm">Kerberos realm.  E.g.: &#x60;ad.it-help.ninja&#x60;. Should be lowercased (actual validation is case-insensitive though)..</param>
        /// <param name="lifetime">The validity duration in seconds for the session token.  This value cannot exceed 2 hours. (required).</param>
        /// <param name="protocol">Protocol for the session (e.g.: \&quot;rdp\&quot;).</param>
        /// <param name="sessionId">Unique ID for this session.</param>
        public SessionTokenSignRequest(SessionTokenContentType contentType = default(SessionTokenContentType), string destination = default(string), string krbKdc = default(string), string krbRealm = default(string), long lifetime = default(long), string protocol = default(string), Guid? sessionId = default(Guid?))
        {
            this.ContentType = contentType;
            this.Lifetime = lifetime;
            this.Destination = destination;
            this.KrbKdc = krbKdc;
            this.KrbRealm = krbRealm;
            this.Protocol = protocol;
            this.SessionId = sessionId;
        }

        /// <summary>
        /// Destination host
        /// </summary>
        /// <value>Destination host</value>
        [DataMember(Name = "destination", EmitDefaultValue = true)]
        public string Destination { get; set; }

        /// <summary>
        /// Kerberos KDC address.  E.g.: &#x60;tcp://IT-HELP-DC.ad.it-help.ninja:88&#x60;. Default scheme is &#x60;tcp&#x60;. Default port is &#x60;88&#x60;.
        /// </summary>
        /// <value>Kerberos KDC address.  E.g.: &#x60;tcp://IT-HELP-DC.ad.it-help.ninja:88&#x60;. Default scheme is &#x60;tcp&#x60;. Default port is &#x60;88&#x60;.</value>
        [DataMember(Name = "krb_kdc", EmitDefaultValue = true)]
        public string KrbKdc { get; set; }

        /// <summary>
        /// Kerberos realm.  E.g.: &#x60;ad.it-help.ninja&#x60;. Should be lowercased (actual validation is case-insensitive though).
        /// </summary>
        /// <value>Kerberos realm.  E.g.: &#x60;ad.it-help.ninja&#x60;. Should be lowercased (actual validation is case-insensitive though).</value>
        [DataMember(Name = "krb_realm", EmitDefaultValue = true)]
        public string KrbRealm { get; set; }

        /// <summary>
        /// The validity duration in seconds for the session token.  This value cannot exceed 2 hours.
        /// </summary>
        /// <value>The validity duration in seconds for the session token.  This value cannot exceed 2 hours.</value>
        [DataMember(Name = "lifetime", IsRequired = true, EmitDefaultValue = true)]
        public long Lifetime { get; set; }

        /// <summary>
        /// Protocol for the session (e.g.: \&quot;rdp\&quot;)
        /// </summary>
        /// <value>Protocol for the session (e.g.: \&quot;rdp\&quot;)</value>
        [DataMember(Name = "protocol", EmitDefaultValue = true)]
        public string Protocol { get; set; }

        /// <summary>
        /// Unique ID for this session
        /// </summary>
        /// <value>Unique ID for this session</value>
        [DataMember(Name = "session_id", EmitDefaultValue = true)]
        public Guid? SessionId { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class SessionTokenSignRequest {\n");
            sb.Append("  ContentType: ").Append(ContentType).Append("\n");
            sb.Append("  Destination: ").Append(Destination).Append("\n");
            sb.Append("  KrbKdc: ").Append(KrbKdc).Append("\n");
            sb.Append("  KrbRealm: ").Append(KrbRealm).Append("\n");
            sb.Append("  Lifetime: ").Append(Lifetime).Append("\n");
            sb.Append("  Protocol: ").Append(Protocol).Append("\n");
            sb.Append("  SessionId: ").Append(SessionId).Append("\n");
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
            // Lifetime (long) minimum
            if (this.Lifetime < (long)0)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for Lifetime, must be a value greater than or equal to 0.", new [] { "Lifetime" });
            }

            yield break;
        }
    }

}
