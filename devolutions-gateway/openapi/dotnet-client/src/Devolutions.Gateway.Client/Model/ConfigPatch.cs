/*
 * devolutions-gateway
 *
 * Protocol-aware fine-grained relay server
 *
 * The version of the OpenAPI document: 2024.3.4
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
    /// ConfigPatch
    /// </summary>
    [DataContract(Name = "ConfigPatch")]
    public partial class ConfigPatch : IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigPatch" /> class.
        /// </summary>
        /// <param name="id">This Gateway&#39;s unique ID.</param>
        /// <param name="subProvisionerPublicKey">subProvisionerPublicKey.</param>
        /// <param name="subscriber">subscriber.</param>
        public ConfigPatch(Guid? id = default(Guid?), SubProvisionerKey subProvisionerPublicKey = default(SubProvisionerKey), Subscriber subscriber = default(Subscriber))
        {
            this.Id = id;
            this.SubProvisionerPublicKey = subProvisionerPublicKey;
            this.Subscriber = subscriber;
        }

        /// <summary>
        /// This Gateway&#39;s unique ID
        /// </summary>
        /// <value>This Gateway&#39;s unique ID</value>
        [DataMember(Name = "Id", EmitDefaultValue = true)]
        public Guid? Id { get; set; }

        /// <summary>
        /// Gets or Sets SubProvisionerPublicKey
        /// </summary>
        [DataMember(Name = "SubProvisionerPublicKey", EmitDefaultValue = true)]
        public SubProvisionerKey SubProvisionerPublicKey { get; set; }

        /// <summary>
        /// Gets or Sets Subscriber
        /// </summary>
        [DataMember(Name = "Subscriber", EmitDefaultValue = true)]
        public Subscriber Subscriber { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ConfigPatch {\n");
            sb.Append("  Id: ").Append(Id).Append("\n");
            sb.Append("  SubProvisionerPublicKey: ").Append(SubProvisionerPublicKey).Append("\n");
            sb.Append("  Subscriber: ").Append(Subscriber).Append("\n");
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
