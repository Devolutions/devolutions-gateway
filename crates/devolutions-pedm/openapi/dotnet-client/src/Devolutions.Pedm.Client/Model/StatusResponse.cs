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
    /// StatusResponse
    /// </summary>
    [DataContract(Name = "StatusResponse")]
    public partial class StatusResponse : IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="StatusResponse" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected StatusResponse() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="StatusResponse" /> class.
        /// </summary>
        /// <param name="elevated">elevated (required).</param>
        /// <param name="session">session (required).</param>
        /// <param name="temporary">temporary (required).</param>
        public StatusResponse(bool elevated = default(bool), SessionElevationStatus session = default(SessionElevationStatus), TemporaryElevationStatus temporary = default(TemporaryElevationStatus))
        {
            this.Elevated = elevated;
            // to ensure "session" is required (not null)
            if (session == null)
            {
                throw new ArgumentNullException("session is a required property for StatusResponse and cannot be null");
            }
            this.Session = session;
            // to ensure "temporary" is required (not null)
            if (temporary == null)
            {
                throw new ArgumentNullException("temporary is a required property for StatusResponse and cannot be null");
            }
            this.Temporary = temporary;
        }

        /// <summary>
        /// Gets or Sets Elevated
        /// </summary>
        [DataMember(Name = "Elevated", IsRequired = true, EmitDefaultValue = true)]
        public bool Elevated { get; set; }

        /// <summary>
        /// Gets or Sets Session
        /// </summary>
        [DataMember(Name = "Session", IsRequired = true, EmitDefaultValue = true)]
        public SessionElevationStatus Session { get; set; }

        /// <summary>
        /// Gets or Sets Temporary
        /// </summary>
        [DataMember(Name = "Temporary", IsRequired = true, EmitDefaultValue = true)]
        public TemporaryElevationStatus Temporary { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class StatusResponse {\n");
            sb.Append("  Elevated: ").Append(Elevated).Append("\n");
            sb.Append("  Session: ").Append(Session).Append("\n");
            sb.Append("  Temporary: ").Append(Temporary).Append("\n");
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
