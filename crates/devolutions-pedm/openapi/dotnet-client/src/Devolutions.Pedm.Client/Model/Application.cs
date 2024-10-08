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
    /// Application
    /// </summary>
    [DataContract(Name = "Application")]
    public partial class Application : IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Application" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected Application() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="Application" /> class.
        /// </summary>
        /// <param name="commandLine">commandLine (required).</param>
        /// <param name="hash">hash (required).</param>
        /// <param name="path">path (required).</param>
        /// <param name="signature">signature (required).</param>
        /// <param name="user">user (required).</param>
        /// <param name="workingDirectory">workingDirectory (required).</param>
        public Application(List<string> commandLine = default(List<string>), Hash hash = default(Hash), string path = default(string), Signature signature = default(Signature), User user = default(User), string workingDirectory = default(string))
        {
            // to ensure "commandLine" is required (not null)
            if (commandLine == null)
            {
                throw new ArgumentNullException("commandLine is a required property for Application and cannot be null");
            }
            this.CommandLine = commandLine;
            // to ensure "hash" is required (not null)
            if (hash == null)
            {
                throw new ArgumentNullException("hash is a required property for Application and cannot be null");
            }
            this.Hash = hash;
            // to ensure "path" is required (not null)
            if (path == null)
            {
                throw new ArgumentNullException("path is a required property for Application and cannot be null");
            }
            this.Path = path;
            // to ensure "signature" is required (not null)
            if (signature == null)
            {
                throw new ArgumentNullException("signature is a required property for Application and cannot be null");
            }
            this.Signature = signature;
            // to ensure "user" is required (not null)
            if (user == null)
            {
                throw new ArgumentNullException("user is a required property for Application and cannot be null");
            }
            this.User = user;
            // to ensure "workingDirectory" is required (not null)
            if (workingDirectory == null)
            {
                throw new ArgumentNullException("workingDirectory is a required property for Application and cannot be null");
            }
            this.WorkingDirectory = workingDirectory;
        }

        /// <summary>
        /// Gets or Sets CommandLine
        /// </summary>
        [DataMember(Name = "CommandLine", IsRequired = true, EmitDefaultValue = true)]
        public List<string> CommandLine { get; set; }

        /// <summary>
        /// Gets or Sets Hash
        /// </summary>
        [DataMember(Name = "Hash", IsRequired = true, EmitDefaultValue = true)]
        public Hash Hash { get; set; }

        /// <summary>
        /// Gets or Sets Path
        /// </summary>
        [DataMember(Name = "Path", IsRequired = true, EmitDefaultValue = true)]
        public string Path { get; set; }

        /// <summary>
        /// Gets or Sets Signature
        /// </summary>
        [DataMember(Name = "Signature", IsRequired = true, EmitDefaultValue = true)]
        public Signature Signature { get; set; }

        /// <summary>
        /// Gets or Sets User
        /// </summary>
        [DataMember(Name = "User", IsRequired = true, EmitDefaultValue = true)]
        public User User { get; set; }

        /// <summary>
        /// Gets or Sets WorkingDirectory
        /// </summary>
        [DataMember(Name = "WorkingDirectory", IsRequired = true, EmitDefaultValue = true)]
        public string WorkingDirectory { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class Application {\n");
            sb.Append("  CommandLine: ").Append(CommandLine).Append("\n");
            sb.Append("  Hash: ").Append(Hash).Append("\n");
            sb.Append("  Path: ").Append(Path).Append("\n");
            sb.Append("  Signature: ").Append(Signature).Append("\n");
            sb.Append("  User: ").Append(User).Append("\n");
            sb.Append("  WorkingDirectory: ").Append(WorkingDirectory).Append("\n");
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
