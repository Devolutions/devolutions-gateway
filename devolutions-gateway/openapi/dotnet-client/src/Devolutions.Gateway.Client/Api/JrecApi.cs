/*
 * devolutions-gateway
 *
 * Protocol-aware fine-grained relay server
 *
 * The version of the OpenAPI document: 2023.2.1
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

namespace Devolutions.Gateway.Client.Api
{

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public interface IJrecApiSync : IApiAccessor
    {
        #region Synchronous Operations
        /// <summary>
        /// Lists all recordings stored on this instance
        /// </summary>
        /// <remarks>
        /// Lists all recordings stored on this instance
        /// </remarks>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <returns>List&lt;Guid&gt;</returns>
        List<Guid> ListRecordings(int operationIndex = 0);

        /// <summary>
        /// Lists all recordings stored on this instance
        /// </summary>
        /// <remarks>
        /// Lists all recordings stored on this instance
        /// </remarks>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <returns>ApiResponse of List&lt;Guid&gt;</returns>
        ApiResponse<List<Guid>> ListRecordingsWithHttpInfo(int operationIndex = 0);
        /// <summary>
        /// Retrieves a recording file for a given session
        /// </summary>
        /// <remarks>
        /// Retrieves a recording file for a given session
        /// </remarks>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="id">Recorded session ID</param>
        /// <param name="filename">Name of recording file to retrieve</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <returns>System.IO.Stream</returns>
        System.IO.Stream PullRecordingFile(Guid id, string filename, int operationIndex = 0);

        /// <summary>
        /// Retrieves a recording file for a given session
        /// </summary>
        /// <remarks>
        /// Retrieves a recording file for a given session
        /// </remarks>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="id">Recorded session ID</param>
        /// <param name="filename">Name of recording file to retrieve</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <returns>ApiResponse of System.IO.Stream</returns>
        ApiResponse<System.IO.Stream> PullRecordingFileWithHttpInfo(Guid id, string filename, int operationIndex = 0);
        #endregion Synchronous Operations
    }

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public interface IJrecApiAsync : IApiAccessor
    {
        #region Asynchronous Operations
        /// <summary>
        /// Lists all recordings stored on this instance
        /// </summary>
        /// <remarks>
        /// Lists all recordings stored on this instance
        /// </remarks>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="cancellationToken">Cancellation Token to cancel the request.</param>
        /// <returns>Task of List&lt;Guid&gt;</returns>
        System.Threading.Tasks.Task<List<Guid>> ListRecordingsAsync(int operationIndex = 0, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken));

        /// <summary>
        /// Lists all recordings stored on this instance
        /// </summary>
        /// <remarks>
        /// Lists all recordings stored on this instance
        /// </remarks>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="cancellationToken">Cancellation Token to cancel the request.</param>
        /// <returns>Task of ApiResponse (List&lt;Guid&gt;)</returns>
        System.Threading.Tasks.Task<ApiResponse<List<Guid>>> ListRecordingsWithHttpInfoAsync(int operationIndex = 0, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken));
        /// <summary>
        /// Retrieves a recording file for a given session
        /// </summary>
        /// <remarks>
        /// Retrieves a recording file for a given session
        /// </remarks>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="id">Recorded session ID</param>
        /// <param name="filename">Name of recording file to retrieve</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="cancellationToken">Cancellation Token to cancel the request.</param>
        /// <returns>Task of System.IO.Stream</returns>
        System.Threading.Tasks.Task<System.IO.Stream> PullRecordingFileAsync(Guid id, string filename, int operationIndex = 0, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken));

        /// <summary>
        /// Retrieves a recording file for a given session
        /// </summary>
        /// <remarks>
        /// Retrieves a recording file for a given session
        /// </remarks>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="id">Recorded session ID</param>
        /// <param name="filename">Name of recording file to retrieve</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="cancellationToken">Cancellation Token to cancel the request.</param>
        /// <returns>Task of ApiResponse (System.IO.Stream)</returns>
        System.Threading.Tasks.Task<ApiResponse<System.IO.Stream>> PullRecordingFileWithHttpInfoAsync(Guid id, string filename, int operationIndex = 0, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken));
        #endregion Asynchronous Operations
    }

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public interface IJrecApi : IJrecApiSync, IJrecApiAsync
    {

    }

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public partial class JrecApi : IJrecApi
    {
        private Devolutions.Gateway.Client.Client.ExceptionFactory _exceptionFactory = (name, response) => null;

        /// <summary>
        /// Initializes a new instance of the <see cref="JrecApi"/> class.
        /// </summary>
        /// <returns></returns>
        public JrecApi() : this((string)null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JrecApi"/> class.
        /// </summary>
        /// <returns></returns>
        public JrecApi(string basePath)
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
        /// Initializes a new instance of the <see cref="JrecApi"/> class
        /// using Configuration object
        /// </summary>
        /// <param name="configuration">An instance of Configuration</param>
        /// <returns></returns>
        public JrecApi(Devolutions.Gateway.Client.Client.Configuration configuration)
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
        /// Initializes a new instance of the <see cref="JrecApi"/> class
        /// using a Configuration object and client instance.
        /// </summary>
        /// <param name="client">The client interface for synchronous API access.</param>
        /// <param name="asyncClient">The client interface for asynchronous API access.</param>
        /// <param name="configuration">The configuration object.</param>
        public JrecApi(Devolutions.Gateway.Client.Client.ISynchronousClient client, Devolutions.Gateway.Client.Client.IAsynchronousClient asyncClient, Devolutions.Gateway.Client.Client.IReadableConfiguration configuration)
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
        /// Lists all recordings stored on this instance Lists all recordings stored on this instance
        /// </summary>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <returns>List&lt;Guid&gt;</returns>
        public List<Guid> ListRecordings(int operationIndex = 0)
        {
            Devolutions.Gateway.Client.Client.ApiResponse<List<Guid>> localVarResponse = ListRecordingsWithHttpInfo();
            return localVarResponse.Data;
        }

        /// <summary>
        /// Lists all recordings stored on this instance Lists all recordings stored on this instance
        /// </summary>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <returns>ApiResponse of List&lt;Guid&gt;</returns>
        public Devolutions.Gateway.Client.Client.ApiResponse<List<Guid>> ListRecordingsWithHttpInfo(int operationIndex = 0)
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


            localVarRequestOptions.Operation = "JrecApi.ListRecordings";
            localVarRequestOptions.OperationIndex = operationIndex;

            // authentication (scope_token) required
            // bearer authentication required
            if (!string.IsNullOrEmpty(this.Configuration.AccessToken) && !localVarRequestOptions.HeaderParameters.ContainsKey("Authorization"))
            {
                localVarRequestOptions.HeaderParameters.Add("Authorization", "Bearer " + this.Configuration.AccessToken);
            }

            // make the HTTP request
            var localVarResponse = this.Client.Get<List<Guid>>("/jet/jrec/list", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("ListRecordings", localVarResponse);
                if (_exception != null)
                {
                    throw _exception;
                }
            }

            return localVarResponse;
        }

        /// <summary>
        /// Lists all recordings stored on this instance Lists all recordings stored on this instance
        /// </summary>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="cancellationToken">Cancellation Token to cancel the request.</param>
        /// <returns>Task of List&lt;Guid&gt;</returns>
        public async System.Threading.Tasks.Task<List<Guid>> ListRecordingsAsync(int operationIndex = 0, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            Devolutions.Gateway.Client.Client.ApiResponse<List<Guid>> localVarResponse = await ListRecordingsWithHttpInfoAsync(operationIndex, cancellationToken).ConfigureAwait(false);
            return localVarResponse.Data;
        }

        /// <summary>
        /// Lists all recordings stored on this instance Lists all recordings stored on this instance
        /// </summary>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="cancellationToken">Cancellation Token to cancel the request.</param>
        /// <returns>Task of ApiResponse (List&lt;Guid&gt;)</returns>
        public async System.Threading.Tasks.Task<Devolutions.Gateway.Client.Client.ApiResponse<List<Guid>>> ListRecordingsWithHttpInfoAsync(int operationIndex = 0, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
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


            localVarRequestOptions.Operation = "JrecApi.ListRecordings";
            localVarRequestOptions.OperationIndex = operationIndex;

            // authentication (scope_token) required
            // bearer authentication required
            if (!string.IsNullOrEmpty(this.Configuration.AccessToken) && !localVarRequestOptions.HeaderParameters.ContainsKey("Authorization"))
            {
                localVarRequestOptions.HeaderParameters.Add("Authorization", "Bearer " + this.Configuration.AccessToken);
            }

            // make the HTTP request
            var localVarResponse = await this.AsynchronousClient.GetAsync<List<Guid>>("/jet/jrec/list", localVarRequestOptions, this.Configuration, cancellationToken).ConfigureAwait(false);

            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("ListRecordings", localVarResponse);
                if (_exception != null)
                {
                    throw _exception;
                }
            }

            return localVarResponse;
        }

        /// <summary>
        /// Retrieves a recording file for a given session Retrieves a recording file for a given session
        /// </summary>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="id">Recorded session ID</param>
        /// <param name="filename">Name of recording file to retrieve</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <returns>System.IO.Stream</returns>
        public System.IO.Stream PullRecordingFile(Guid id, string filename, int operationIndex = 0)
        {
            Devolutions.Gateway.Client.Client.ApiResponse<System.IO.Stream> localVarResponse = PullRecordingFileWithHttpInfo(id, filename);
            return localVarResponse.Data;
        }

        /// <summary>
        /// Retrieves a recording file for a given session Retrieves a recording file for a given session
        /// </summary>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="id">Recorded session ID</param>
        /// <param name="filename">Name of recording file to retrieve</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <returns>ApiResponse of System.IO.Stream</returns>
        public Devolutions.Gateway.Client.Client.ApiResponse<System.IO.Stream> PullRecordingFileWithHttpInfo(Guid id, string filename, int operationIndex = 0)
        {
            // verify the required parameter 'filename' is set
            if (filename == null)
            {
                throw new Devolutions.Gateway.Client.Client.ApiException(400, "Missing required parameter 'filename' when calling JrecApi->PullRecordingFile");
            }

            Devolutions.Gateway.Client.Client.RequestOptions localVarRequestOptions = new Devolutions.Gateway.Client.Client.RequestOptions();

            string[] _contentTypes = new string[] {
            };

            // to determine the Accept header
            string[] _accepts = new string[] {
                "application/octet-stream"
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

            localVarRequestOptions.PathParameters.Add("id", Devolutions.Gateway.Client.Client.ClientUtils.ParameterToString(id)); // path parameter
            localVarRequestOptions.PathParameters.Add("filename", Devolutions.Gateway.Client.Client.ClientUtils.ParameterToString(filename)); // path parameter

            localVarRequestOptions.Operation = "JrecApi.PullRecordingFile";
            localVarRequestOptions.OperationIndex = operationIndex;

            // authentication (jrec_token) required
            // bearer authentication required
            if (!string.IsNullOrEmpty(this.Configuration.AccessToken) && !localVarRequestOptions.HeaderParameters.ContainsKey("Authorization"))
            {
                localVarRequestOptions.HeaderParameters.Add("Authorization", "Bearer " + this.Configuration.AccessToken);
            }

            // make the HTTP request
            var localVarResponse = this.Client.Get<System.IO.Stream>("/jet/jrec/pull/{id}/{filename}", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("PullRecordingFile", localVarResponse);
                if (_exception != null)
                {
                    throw _exception;
                }
            }

            return localVarResponse;
        }

        /// <summary>
        /// Retrieves a recording file for a given session Retrieves a recording file for a given session
        /// </summary>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="id">Recorded session ID</param>
        /// <param name="filename">Name of recording file to retrieve</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="cancellationToken">Cancellation Token to cancel the request.</param>
        /// <returns>Task of System.IO.Stream</returns>
        public async System.Threading.Tasks.Task<System.IO.Stream> PullRecordingFileAsync(Guid id, string filename, int operationIndex = 0, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            Devolutions.Gateway.Client.Client.ApiResponse<System.IO.Stream> localVarResponse = await PullRecordingFileWithHttpInfoAsync(id, filename, operationIndex, cancellationToken).ConfigureAwait(false);
            return localVarResponse.Data;
        }

        /// <summary>
        /// Retrieves a recording file for a given session Retrieves a recording file for a given session
        /// </summary>
        /// <exception cref="Devolutions.Gateway.Client.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="id">Recorded session ID</param>
        /// <param name="filename">Name of recording file to retrieve</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="cancellationToken">Cancellation Token to cancel the request.</param>
        /// <returns>Task of ApiResponse (System.IO.Stream)</returns>
        public async System.Threading.Tasks.Task<Devolutions.Gateway.Client.Client.ApiResponse<System.IO.Stream>> PullRecordingFileWithHttpInfoAsync(Guid id, string filename, int operationIndex = 0, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            // verify the required parameter 'filename' is set
            if (filename == null)
            {
                throw new Devolutions.Gateway.Client.Client.ApiException(400, "Missing required parameter 'filename' when calling JrecApi->PullRecordingFile");
            }


            Devolutions.Gateway.Client.Client.RequestOptions localVarRequestOptions = new Devolutions.Gateway.Client.Client.RequestOptions();

            string[] _contentTypes = new string[] {
            };

            // to determine the Accept header
            string[] _accepts = new string[] {
                "application/octet-stream"
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

            localVarRequestOptions.PathParameters.Add("id", Devolutions.Gateway.Client.Client.ClientUtils.ParameterToString(id)); // path parameter
            localVarRequestOptions.PathParameters.Add("filename", Devolutions.Gateway.Client.Client.ClientUtils.ParameterToString(filename)); // path parameter

            localVarRequestOptions.Operation = "JrecApi.PullRecordingFile";
            localVarRequestOptions.OperationIndex = operationIndex;

            // authentication (jrec_token) required
            // bearer authentication required
            if (!string.IsNullOrEmpty(this.Configuration.AccessToken) && !localVarRequestOptions.HeaderParameters.ContainsKey("Authorization"))
            {
                localVarRequestOptions.HeaderParameters.Add("Authorization", "Bearer " + this.Configuration.AccessToken);
            }

            // make the HTTP request
            var localVarResponse = await this.AsynchronousClient.GetAsync<System.IO.Stream>("/jet/jrec/pull/{id}/{filename}", localVarRequestOptions, this.Configuration, cancellationToken).ConfigureAwait(false);

            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("PullRecordingFile", localVarResponse);
                if (_exception != null)
                {
                    throw _exception;
                }
            }

            return localVarResponse;
        }

    }
}
