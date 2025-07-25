/*
 * devolutions-gateway-subscriber
 *
 * API a service must implement in order to receive Devolutions Gateway notifications
 *
 * The version of the OpenAPI document: 2025.2.2
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
        /// Event type for messages.
        /// </summary>
        /// <value>Event type for messages.</value>
        [TypeConverter(typeof(CustomEnumConverter<SubscriberMessageKind>))]
        [JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public enum SubscriberMessageKind
        {
            
            /// <summary>
            /// Enum Started for session.started
            /// </summary>
            [EnumMember(Value = "session.started")]
            Started = 1,
            
            /// <summary>
            /// Enum Ended for session.ended
            /// </summary>
            [EnumMember(Value = "session.ended")]
            Ended = 2,
            
            /// <summary>
            /// Enum List for session.list
            /// </summary>
            [EnumMember(Value = "session.list")]
            List = 3
        }
}
