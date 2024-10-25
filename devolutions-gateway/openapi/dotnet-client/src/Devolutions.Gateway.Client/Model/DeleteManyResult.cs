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
    /// DeleteManyResult
    /// </summary>
    [DataContract(Name = "DeleteManyResult")]
    public partial class DeleteManyResult : IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DeleteManyResult" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected DeleteManyResult() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="DeleteManyResult" /> class.
        /// </summary>
        /// <param name="foundCount">Number of recordings found (required).</param>
        /// <param name="notFoundCount">Number of recordings not found (required).</param>
        public DeleteManyResult(int foundCount = default(int), int notFoundCount = default(int))
        {
            this.FoundCount = foundCount;
            this.NotFoundCount = notFoundCount;
        }

        /// <summary>
        /// Number of recordings found
        /// </summary>
        /// <value>Number of recordings found</value>
        [DataMember(Name = "found_count", IsRequired = true, EmitDefaultValue = true)]
        public int FoundCount { get; set; }

        /// <summary>
        /// Number of recordings not found
        /// </summary>
        /// <value>Number of recordings not found</value>
        [DataMember(Name = "not_found_count", IsRequired = true, EmitDefaultValue = true)]
        public int NotFoundCount { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class DeleteManyResult {\n");
            sb.Append("  FoundCount: ").Append(FoundCount).Append("\n");
            sb.Append("  NotFoundCount: ").Append(NotFoundCount).Append("\n");
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
            // FoundCount (int) minimum
            if (this.FoundCount < (int)0)
            {
                yield return new ValidationResult("Invalid value for FoundCount, must be a value greater than or equal to 0.", new [] { "FoundCount" });
            }

            // NotFoundCount (int) minimum
            if (this.NotFoundCount < (int)0)
            {
                yield return new ValidationResult("Invalid value for NotFoundCount, must be a value greater than or equal to 0.", new [] { "NotFoundCount" });
            }

            yield break;
        }
    }

}
