/*
 * devolutions-gateway
 *
 * Protocol-aware fine-grained relay server
 *
 * The version of the OpenAPI document: 2023.2.3
 * Contact: infos@devolutions.net
 * Generated by: https://github.com/openapitools/openapi-generator.git
 */


using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Net.Mime;
using Devolutions.Gateway.Client.Client;
using Devolutions.Gateway.Client.Model;

namespace Devolutions.Gateway.Client.Api
{

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public interface IHeartbeatApiSync : IApiAccessor
    {
        #region Synchronous Operations
        /// <summary>
        /// Performs a heartbeat check
        /// </summary>
        /// <remarks>
        /// Performs a heartbeat check
        /// </remarks>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <returns>Heartbeat</returns>
        Heartbeat GetHeartbeat(int operationIndex = 0);

        /// <summary>
        /// Performs a heartbeat check
        /// </summary>
        /// <remarks>
        /// Performs a heartbeat check
        /// </remarks>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <returns>ApiResponse of Heartbeat</returns>
        ApiResponse<Heartbeat> GetHeartbeatWithHttpInfo(int operationIndex = 0);
        #endregion Synchronous Operations
    }

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public interface IHeartbeatApiAsync : IApiAccessor
    {
        #region Asynchronous Operations
        /// <summary>
        /// Performs a heartbeat check
        /// </summary>
        /// <remarks>
        /// Performs a heartbeat check
        /// </remarks>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="cancellationToken">Cancellation Token to cancel the request.</param>
        /// <returns>Task of Heartbeat</returns>
        System.Threading.Tasks.Task<Heartbeat> GetHeartbeatAsync(int operationIndex = 0, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken));

        /// <summary>
        /// Performs a heartbeat check
        /// </summary>
        /// <remarks>
        /// Performs a heartbeat check
        /// </remarks>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="cancellationToken">Cancellation Token to cancel the request.</param>
        /// <returns>Task of ApiResponse (Heartbeat)</returns>
        System.Threading.Tasks.Task<ApiResponse<Heartbeat>> GetHeartbeatWithHttpInfoAsync(int operationIndex = 0, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken));
        #endregion Asynchronous Operations
    }

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public interface IHeartbeatApi : IHeartbeatApiSync, IHeartbeatApiAsync
    {

    }

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public partial class HeartbeatApi : IHeartbeatApi
    {
        private Devolutions.Gateway.Client.Client.ExceptionFactory _exceptionFactory = (name, response) => null;

        /// <summary>
        /// Initializes a new instance of the <see cref="HeartbeatApi"/> class.
        /// </summary>
        /// <returns></returns>
        public HeartbeatApi() : this((string)null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HeartbeatApi"/> class.
        /// </summary>
        /// <returns></returns>
        public HeartbeatApi(string basePath)
        {
            this.Configuration = Devolutions.Gateway.Client.Client.Configuration.MergeConfigurations(
                Devolutions.Gateway.Client.Client.GlobalConfiguration.Instance,
                new Devolutions.Gateway.Client.Client.Configuration { BasePath = basePath }
            );
            this.Client = new Devolutions.Gateway.Client.Client.ApiClient(this.Configuration.BasePath);
            this.AsynchronousClient = new Devolutions.Gateway.Client.Client.ApiClient(this.Configuration.BasePath);
            this.ExceptionFactory = Devolutions.Gateway.Client.Client.Configuration.DefaultExceptionFactory;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HeartbeatApi"/> class
        /// using Configuration object
        /// </summary>
        /// <param name="configuration">An instance of Configuration</param>
        /// <returns></returns>
        public HeartbeatApi(Devolutions.Gateway.Client.Client.Configuration configuration)
        {
            if (configuration == null) throw new ArgumentNullException("configuration");

            this.Configuration = Devolutions.Gateway.Client.Client.Configuration.MergeConfigurations(
                Devolutions.Gateway.Client.Client.GlobalConfiguration.Instance,
                configuration
            );
            this.Client = new Devolutions.Gateway.Client.Client.ApiClient(this.Configuration.BasePath);
            this.AsynchronousClient = new Devolutions.Gateway.Client.Client.ApiClient(this.Configuration.BasePath);
            ExceptionFactory = Devolutions.Gateway.Client.Client.Configuration.DefaultExceptionFactory;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HeartbeatApi"/> class
        /// using a Configuration object and client instance.
        /// </summary>
        /// <param name="client">The client interface for synchronous API access.</param>
        /// <param name="asyncClient">The client interface for asynchronous API access.</param>
        /// <param name="configuration">The configuration object.</param>
        public HeartbeatApi(Devolutions.Gateway.Client.Client.ISynchronousClient client, Devolutions.Gateway.Client.Client.IAsynchronousClient asyncClient, Devolutions.Gateway.Client.Client.IReadableConfiguration configuration)
        {
            if (client == null) throw new ArgumentNullException("client");
            if (asyncClient == null) throw new ArgumentNullException("asyncClient");
            if (configuration == null) throw new ArgumentNullException("configuration");

            this.Client = client;
            this.AsynchronousClient = asyncClient;
            this.Configuration = configuration;
            this.ExceptionFactory = Devolutions.Gateway.Client.Client.Configuration.DefaultExceptionFactory;
        }

        /// <summary>
        /// The client for accessing this underlying API asynchronously.
        /// </summary>
        public Devolutions.Gateway.Client.Client.IAsynchronousClient AsynchronousClient { get; set; }

        /// <summary>
        /// The client for accessing this underlying API synchronously.
        /// </summary>
        public Devolutions.Gateway.Client.Client.ISynchronousClient Client { get; set; }

        /// <summary>
        /// Gets the base path of the API client.
        /// </summary>
        /// <value>The base path</value>
        public string GetBasePath()
        {
            return this.Configuration.BasePath;
        }

        /// <summary>
        /// Gets or sets the configuration object
        /// </summary>
        /// <value>An instance of the Configuration</value>
        public Devolutions.Gateway.Client.Client.IReadableConfiguration Configuration { get; set; }

        /// <summary>
        /// Provides a factory method hook for the creation of exceptions.
        /// </summary>
        public Devolutions.Gateway.Client.Client.ExceptionFactory ExceptionFactory
        {
            get
            {
                if (_exceptionFactory != null && _exceptionFactory.GetInvocationList().Length > 1)
                {
                    throw new InvalidOperationException("Multicast delegate for ExceptionFactory is unsupported.");
                }
                return _exceptionFactory;
            }
            set { _exceptionFactory = value; }
        }

        /// <summary>
        /// Performs a heartbeat check Performs a heartbeat check
        /// </summary>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <returns>Heartbeat</returns>
        public Heartbeat GetHeartbeat(int operationIndex = 0)
        {
            Devolutions.Gateway.Client.Client.ApiResponse<Heartbeat> localVarResponse = GetHeartbeatWithHttpInfo();
            return localVarResponse.Data;
        }

        /// <summary>
        /// Performs a heartbeat check Performs a heartbeat check
        /// </summary>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <returns>ApiResponse of Heartbeat</returns>
        public Devolutions.Gateway.Client.Client.ApiResponse<Heartbeat> GetHeartbeatWithHttpInfo(int operationIndex = 0)
        {
            Devolutions.Gateway.Client.Client.RequestOptions localVarRequestOptions = new Devolutions.Gateway.Client.Client.RequestOptions();

            string[] _contentTypes = new string[] {
            };

            // to determine the Accept header
            string[] _accepts = new string[] {
                "application/json"
            };

            var localVarContentType = Devolutions.Gateway.Client.Client.ClientUtils.SelectHeaderContentType(_contentTypes);
            if (localVarContentType != null)
            {
                localVarRequestOptions.HeaderParameters.Add("Content-Type", localVarContentType);
            }

            var localVarAccept = Devolutions.Gateway.Client.Client.ClientUtils.SelectHeaderAccept(_accepts);
            if (localVarAccept != null)
            {
                localVarRequestOptions.HeaderParameters.Add("Accept", localVarAccept);
            }


            localVarRequestOptions.Operation = "HeartbeatApi.GetHeartbeat";
            localVarRequestOptions.OperationIndex = operationIndex;

            // authentication (scope_token) required
            // bearer authentication required
            if (!string.IsNullOrEmpty(this.Configuration.AccessToken) && !localVarRequestOptions.HeaderParameters.ContainsKey("Authorization"))
            {
                localVarRequestOptions.HeaderParameters.Add("Authorization", "Bearer " + this.Configuration.AccessToken);
            }

            // make the HTTP request
            var localVarResponse = this.Client.Get<Heartbeat>("/jet/heartbeat", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("GetHeartbeat", localVarResponse);
                if (_exception != null)
                {
                    throw _exception;
                }
            }

            return localVarResponse;
        }

        /// <summary>
        /// Performs a heartbeat check Performs a heartbeat check
        /// </summary>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="cancellationToken">Cancellation Token to cancel the request.</param>
        /// <returns>Task of Heartbeat</returns>
        public async System.Threading.Tasks.Task<Heartbeat> GetHeartbeatAsync(int operationIndex = 0, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            Devolutions.Gateway.Client.Client.ApiResponse<Heartbeat> localVarResponse = await GetHeartbeatWithHttpInfoAsync(operationIndex, cancellationToken).ConfigureAwait(false);
            return localVarResponse.Data;
        }

        /// <summary>
        /// Performs a heartbeat check Performs a heartbeat check
        /// </summary>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="cancellationToken">Cancellation Token to cancel the request.</param>
        /// <returns>Task of ApiResponse (Heartbeat)</returns>
        public async System.Threading.Tasks.Task<Devolutions.Gateway.Client.Client.ApiResponse<Heartbeat>> GetHeartbeatWithHttpInfoAsync(int operationIndex = 0, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {

            Devolutions.Gateway.Client.Client.RequestOptions localVarRequestOptions = new Devolutions.Gateway.Client.Client.RequestOptions();

            string[] _contentTypes = new string[] {
            };

            // to determine the Accept header
            string[] _accepts = new string[] {
                "application/json"
            };

            var localVarContentType = Devolutions.Gateway.Client.Client.ClientUtils.SelectHeaderContentType(_contentTypes);
            if (localVarContentType != null)
            {
                localVarRequestOptions.HeaderParameters.Add("Content-Type", localVarContentType);
            }

            var localVarAccept = Devolutions.Gateway.Client.Client.ClientUtils.SelectHeaderAccept(_accepts);
            if (localVarAccept != null)
            {
                localVarRequestOptions.HeaderParameters.Add("Accept", localVarAccept);
            }


            localVarRequestOptions.Operation = "HeartbeatApi.GetHeartbeat";
            localVarRequestOptions.OperationIndex = operationIndex;

            // authentication (scope_token) required
            // bearer authentication required
            if (!string.IsNullOrEmpty(this.Configuration.AccessToken) && !localVarRequestOptions.HeaderParameters.ContainsKey("Authorization"))
            {
                localVarRequestOptions.HeaderParameters.Add("Authorization", "Bearer " + this.Configuration.AccessToken);
            }

            // make the HTTP request
            var localVarResponse = await this.AsynchronousClient.GetAsync<Heartbeat>("/jet/heartbeat", localVarRequestOptions, this.Configuration, cancellationToken).ConfigureAwait(false);

            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("GetHeartbeat", localVarResponse);
                if (_exception != null)
                {
                    throw _exception;
                }
            }

            return localVarResponse;
        }

    }
}
