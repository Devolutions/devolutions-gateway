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
    /// JitElevationLogPage
    /// </summary>
    [DataContract(Name = "JitElevationLogPage")]
    public partial class JitElevationLogPage : IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="JitElevationLogPage" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected JitElevationLogPage() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="JitElevationLogPage" /> class.
        /// </summary>
        /// <param name="results">results (required).</param>
        /// <param name="totalPages">totalPages (required).</param>
        /// <param name="totalRecords">totalRecords (required).</param>
        public JitElevationLogPage(List<JitElevationLogRow> results = default(List<JitElevationLogRow>), int totalPages = default(int), int totalRecords = default(int))
        {
            // to ensure "results" is required (not null)
            if (results == null)
            {
                throw new ArgumentNullException("results is a required property for JitElevationLogPage and cannot be null");
            }
            this.Results = results;
            this.TotalPages = totalPages;
            this.TotalRecords = totalRecords;
        }

        /// <summary>
        /// Gets or Sets Results
        /// </summary>
        [DataMember(Name = "Results", IsRequired = true, EmitDefaultValue = true)]
        public List<JitElevationLogRow> Results { get; set; }

        /// <summary>
        /// Gets or Sets TotalPages
        /// </summary>
        [DataMember(Name = "TotalPages", IsRequired = true, EmitDefaultValue = true)]
        public int TotalPages { get; set; }

        /// <summary>
        /// Gets or Sets TotalRecords
        /// </summary>
        [DataMember(Name = "TotalRecords", IsRequired = true, EmitDefaultValue = true)]
        public int TotalRecords { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class JitElevationLogPage {\n");
            sb.Append("  Results: ").Append(Results).Append("\n");
            sb.Append("  TotalPages: ").Append(TotalPages).Append("\n");
            sb.Append("  TotalRecords: ").Append(TotalRecords).Append("\n");
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
            // TotalPages (int) minimum
            if (this.TotalPages < (int)0)
            {
                yield return new ValidationResult("Invalid value for TotalPages, must be a value greater than or equal to 0.", new [] { "TotalPages" });
            }

            // TotalRecords (int) minimum
            if (this.TotalRecords < (int)0)
            {
                yield return new ValidationResult("Invalid value for TotalRecords, must be a value greater than or equal to 0.", new [] { "TotalRecords" });
            }

            yield break;
        }
    }

}
