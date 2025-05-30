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
    /// JitElevationLogRow
    /// </summary>
    [DataContract(Name = "JitElevationLogRow")]
    public partial class JitElevationLogRow : IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="JitElevationLogRow" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected JitElevationLogRow() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="JitElevationLogRow" /> class.
        /// </summary>
        /// <param name="askerPath">askerPath.</param>
        /// <param name="id">id (required).</param>
        /// <param name="success">success (required).</param>
        /// <param name="targetCommandLine">targetCommandLine.</param>
        /// <param name="targetHash">targetHash.</param>
        /// <param name="targetPath">targetPath.</param>
        /// <param name="targetSignature">targetSignature.</param>
        /// <param name="targetWorkingDirectory">targetWorkingDirectory.</param>
        /// <param name="timestamp">timestamp (required).</param>
        /// <param name="user">user.</param>
        public JitElevationLogRow(string askerPath = default(string), long id = default(long), long success = default(long), string targetCommandLine = default(string), Hash targetHash = default(Hash), string targetPath = default(string), Signature targetSignature = default(Signature), string targetWorkingDirectory = default(string), long timestamp = default(long), User user = default(User))
        {
            this.Id = id;
            this.Success = success;
            this.Timestamp = timestamp;
            this.AskerPath = askerPath;
            this.TargetCommandLine = targetCommandLine;
            this.TargetHash = targetHash;
            this.TargetPath = targetPath;
            this.TargetSignature = targetSignature;
            this.TargetWorkingDirectory = targetWorkingDirectory;
            this.User = user;
        }

        /// <summary>
        /// Gets or Sets AskerPath
        /// </summary>
        [DataMember(Name = "AskerPath", EmitDefaultValue = false)]
        public string AskerPath { get; set; }

        /// <summary>
        /// Gets or Sets Id
        /// </summary>
        [DataMember(Name = "Id", IsRequired = true, EmitDefaultValue = true)]
        public long Id { get; set; }

        /// <summary>
        /// Gets or Sets Success
        /// </summary>
        [DataMember(Name = "Success", IsRequired = true, EmitDefaultValue = true)]
        public long Success { get; set; }

        /// <summary>
        /// Gets or Sets TargetCommandLine
        /// </summary>
        [DataMember(Name = "TargetCommandLine", EmitDefaultValue = false)]
        public string TargetCommandLine { get; set; }

        /// <summary>
        /// Gets or Sets TargetHash
        /// </summary>
        [DataMember(Name = "TargetHash", EmitDefaultValue = false)]
        public Hash TargetHash { get; set; }

        /// <summary>
        /// Gets or Sets TargetPath
        /// </summary>
        [DataMember(Name = "TargetPath", EmitDefaultValue = false)]
        public string TargetPath { get; set; }

        /// <summary>
        /// Gets or Sets TargetSignature
        /// </summary>
        [DataMember(Name = "TargetSignature", EmitDefaultValue = false)]
        public Signature TargetSignature { get; set; }

        /// <summary>
        /// Gets or Sets TargetWorkingDirectory
        /// </summary>
        [DataMember(Name = "TargetWorkingDirectory", EmitDefaultValue = false)]
        public string TargetWorkingDirectory { get; set; }

        /// <summary>
        /// Gets or Sets Timestamp
        /// </summary>
        [DataMember(Name = "Timestamp", IsRequired = true, EmitDefaultValue = true)]
        public long Timestamp { get; set; }

        /// <summary>
        /// Gets or Sets User
        /// </summary>
        [DataMember(Name = "User", EmitDefaultValue = false)]
        public User User { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class JitElevationLogRow {\n");
            sb.Append("  AskerPath: ").Append(AskerPath).Append("\n");
            sb.Append("  Id: ").Append(Id).Append("\n");
            sb.Append("  Success: ").Append(Success).Append("\n");
            sb.Append("  TargetCommandLine: ").Append(TargetCommandLine).Append("\n");
            sb.Append("  TargetHash: ").Append(TargetHash).Append("\n");
            sb.Append("  TargetPath: ").Append(TargetPath).Append("\n");
            sb.Append("  TargetSignature: ").Append(TargetSignature).Append("\n");
            sb.Append("  TargetWorkingDirectory: ").Append(TargetWorkingDirectory).Append("\n");
            sb.Append("  Timestamp: ").Append(Timestamp).Append("\n");
            sb.Append("  User: ").Append(User).Append("\n");
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
