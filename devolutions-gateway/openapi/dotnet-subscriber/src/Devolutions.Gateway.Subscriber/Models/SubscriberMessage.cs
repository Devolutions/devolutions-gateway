/*
 * devolutions-gateway-subscriber
 *
 * API a service must implement in order to receive Devolutions Gateway notifications
 *
 * The version of the OpenAPI document: 2023.3.0
 * Contact: infos@devolutions.net
 * Generated by: https://openapi-generator.tech
 */

using System;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Runtime.Serialization;
using Newtonsoft.Json;
using Devolutions.Gateway.Subscriber.Converters;

namespace Devolutions.Gateway.Subscriber.Models
{ 
    /// <summary>
    /// Message produced on various Gateway events
    /// </summary>
    [DataContract]
    public class SubscriberMessage : IEquatable<SubscriberMessage>
    {
        /// <summary>
        /// Gets or Sets Kind
        /// </summary>
        [Required]
        [DataMember(Name="kind", EmitDefaultValue=true)]
        public SubscriberMessageKind Kind { get; set; }

        /// <summary>
        /// Gets or Sets Session
        /// </summary>
        [DataMember(Name="session", EmitDefaultValue=true)]
        public SubscriberSessionInfo Session { get; set; }

        /// <summary>
        /// Session list associated to this event
        /// </summary>
        /// <value>Session list associated to this event</value>
        [DataMember(Name="session_list", EmitDefaultValue=true)]
        public List<SubscriberSessionInfo> SessionList { get; set; }

        /// <summary>
        /// Date and time this message was produced
        /// </summary>
        /// <value>Date and time this message was produced</value>
        [Required]
        [DataMember(Name="timestamp", EmitDefaultValue=false)]
        public DateTime Timestamp { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class SubscriberMessage {\n");
            sb.Append("  Kind: ").Append(Kind).Append("\n");
            sb.Append("  Session: ").Append(Session).Append("\n");
            sb.Append("  SessionList: ").Append(SessionList).Append("\n");
            sb.Append("  Timestamp: ").Append(Timestamp).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public string ToJson()
        {
            return Newtonsoft.Json.JsonConvert.SerializeObject(this, Newtonsoft.Json.Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="obj">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object obj)
        {
            if (obj is null) return false;
            if (ReferenceEquals(this, obj)) return true;
            return obj.GetType() == GetType() && Equals((SubscriberMessage)obj);
        }

        /// <summary>
        /// Returns true if SubscriberMessage instances are equal
        /// </summary>
        /// <param name="other">Instance of SubscriberMessage to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(SubscriberMessage other)
        {
            if (other is null) return false;
            if (ReferenceEquals(this, other)) return true;

            return 
                (
                    Kind == other.Kind ||
                    
                    Kind.Equals(other.Kind)
                ) && 
                (
                    Session == other.Session ||
                    Session != null &&
                    Session.Equals(other.Session)
                ) && 
                (
                    SessionList == other.SessionList ||
                    SessionList != null &&
                    other.SessionList != null &&
                    SessionList.SequenceEqual(other.SessionList)
                ) && 
                (
                    Timestamp == other.Timestamp ||
                    Timestamp != null &&
                    Timestamp.Equals(other.Timestamp)
                );
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                var hashCode = 41;
                // Suitable nullity checks etc, of course :)
                    
                    hashCode = hashCode * 59 + Kind.GetHashCode();
                    if (Session != null)
                    hashCode = hashCode * 59 + Session.GetHashCode();
                    if (SessionList != null)
                    hashCode = hashCode * 59 + SessionList.GetHashCode();
                    if (Timestamp != null)
                    hashCode = hashCode * 59 + Timestamp.GetHashCode();
                return hashCode;
            }
        }

        #region Operators
        #pragma warning disable 1591

        public static bool operator ==(SubscriberMessage left, SubscriberMessage right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(SubscriberMessage left, SubscriberMessage right)
        {
            return !Equals(left, right);
        }

        #pragma warning restore 1591
        #endregion Operators
    }
}
