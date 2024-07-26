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
    /// Profile
    /// </summary>
    [DataContract(Name = "Profile")]
    public partial class Profile : IValidatableObject
    {

        /// <summary>
        /// Gets or Sets DefaultElevationKind
        /// </summary>
        [DataMember(Name = "DefaultElevationKind", EmitDefaultValue = false)]
        public ElevationKind? DefaultElevationKind { get; set; }

        /// <summary>
        /// Gets or Sets ElevationMethod
        /// </summary>
        [DataMember(Name = "ElevationMethod", EmitDefaultValue = false)]
        public ElevationMethod? ElevationMethod { get; set; }
        /// <summary>
        /// Initializes a new instance of the <see cref="Profile" /> class.
        /// </summary>
        /// <param name="defaultElevationKind">defaultElevationKind.</param>
        /// <param name="elevationMethod">elevationMethod.</param>
        /// <param name="elevationSettings">elevationSettings.</param>
        /// <param name="id">id.</param>
        /// <param name="name">name (default to &quot;Unnamed profile&quot;).</param>
        /// <param name="promptSecureDesktop">promptSecureDesktop (default to true).</param>
        /// <param name="rules">rules.</param>
        public Profile(ElevationKind? defaultElevationKind = default(ElevationKind?), ElevationMethod? elevationMethod = default(ElevationMethod?), ElevationConfigurations elevationSettings = default(ElevationConfigurations), string id = default(string), string name = @"Unnamed profile", bool promptSecureDesktop = true, List<string> rules = default(List<string>))
        {
            this.DefaultElevationKind = defaultElevationKind;
            this.ElevationMethod = elevationMethod;
            this.ElevationSettings = elevationSettings;
            this.Id = id;
            // use default value if no "name" provided
            this.Name = name ?? @"Unnamed profile";
            this.PromptSecureDesktop = promptSecureDesktop;
            this.Rules = rules;
        }

        /// <summary>
        /// Gets or Sets ElevationSettings
        /// </summary>
        [DataMember(Name = "ElevationSettings", EmitDefaultValue = false)]
        public ElevationConfigurations ElevationSettings { get; set; }

        /// <summary>
        /// Gets or Sets Id
        /// </summary>
        [DataMember(Name = "Id", EmitDefaultValue = false)]
        public string Id { get; set; }

        /// <summary>
        /// Gets or Sets Name
        /// </summary>
        [DataMember(Name = "Name", EmitDefaultValue = false)]
        public string Name { get; set; }

        /// <summary>
        /// Gets or Sets PromptSecureDesktop
        /// </summary>
        [DataMember(Name = "PromptSecureDesktop", EmitDefaultValue = true)]
        public bool PromptSecureDesktop { get; set; }

        /// <summary>
        /// Gets or Sets Rules
        /// </summary>
        [DataMember(Name = "Rules", EmitDefaultValue = false)]
        public List<string> Rules { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class Profile {\n");
            sb.Append("  DefaultElevationKind: ").Append(DefaultElevationKind).Append("\n");
            sb.Append("  ElevationMethod: ").Append(ElevationMethod).Append("\n");
            sb.Append("  ElevationSettings: ").Append(ElevationSettings).Append("\n");
            sb.Append("  Id: ").Append(Id).Append("\n");
            sb.Append("  Name: ").Append(Name).Append("\n");
            sb.Append("  PromptSecureDesktop: ").Append(PromptSecureDesktop).Append("\n");
            sb.Append("  Rules: ").Append(Rules).Append("\n");
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
