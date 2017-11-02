/*
 * Copyright 2015, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 *    * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.google.auth.oauth2;

import static com.google.common.base.MoreObjects.firstNonNull;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.GenericData;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.base.MoreObjects;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Date;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * OAuth2 credentials representing the built-in service account for a Google Compute Engine VM.
 *
 * <p>Fetches access tokens from the Google Compute Engine metadata server.
 */
public class ComputeEngineCredentials extends GoogleCredentials {

  private static final Logger LOGGER = Logger.getLogger(ComputeEngineCredentials.class.getName());

  // Note: the explicit IP address is used to avoid name server resolution issues.
  static final String DEFAULT_METADATA_SERVER_URL = "http://169.254.169.254";

  // Note: the explicit `timeout` and `tries` below is a workaround. The underlying
  // issue is that resolving an unknown host on some networks will take
  // 20-30 seconds; making this timeout short fixes the issue, but
  // could lead to false negatives in the event that we are on GCE, but
  // the metadata resolution was particularly slow. The latter case is
  // "unlikely" since the expected 4-nines time is about 0.5 seconds.
  // This allows us to limit the total ping maximum timeout to 1.5 seconds
  // for developer desktop scenarios.
  static final int MAX_COMPUTE_PING_TRIES = 3;
  static final int COMPUTE_PING_CONNECTION_TIMEOUT_MS = 500;

  private static final String PARSE_ERROR_PREFIX = "Error parsing token refresh response. ";
  private static final long serialVersionUID = -4113476462526554235L;

  private final String transportFactoryClassName;

  private transient HttpTransportFactory transportFactory;

  /**
   * Returns a credentials instance from the given transport factory
   *
   * @param transportFactory The Http transport factory
   * @return the credential instance
   * @deprecated Use {@link #newBuilder()} instead. This constructor will either be deleted or made
   *             private in a later version.
   */
  @Deprecated
  public static ComputeEngineCredentials of(HttpTransportFactory transportFactory) {
    return ComputeEngineCredentials.newBuilder().setHttpTransportFactory(transportFactory).build();
  }

  /**
   * Create a new ComputeEngineCredentials instance with default behavior.
   *
   * @deprecated Use {@link #create()} instead. This constructor will either be deleted or
   *             made private in a later version.
   */
  @Deprecated
  public ComputeEngineCredentials() {
    this(null);
  }

  /**
   * Constructor with overridden transport.
   *
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *        tokens.
   * @deprecated Use {@link #newBuilder()} instead. This constructor will either be deleted or made
   *             private in a later version.
   */
  @Deprecated
  public ComputeEngineCredentials(HttpTransportFactory transportFactory) {
    this.transportFactory = firstNonNull(transportFactory,
        getFromServiceLoader(HttpTransportFactory.class, OAuth2Utils.HTTP_TRANSPORT_FACTORY));
    this.transportFactoryClassName = this.transportFactory.getClass().getName();
  }

  /**
   * Create a new ComputeEngineCredentials instance with default behavior.
   */
  public static ComputeEngineCredentials create() {
    return new ComputeEngineCredentials(null);
  }

  /**
   * Refresh the access token by getting it from the GCE metadata server
   */
  @Override
  public AccessToken refreshAccessToken() throws IOException {
    GenericUrl tokenUrl = new GenericUrl(getTokenServerEncodedUrl());
    HttpRequest request =
        transportFactory.create().createRequestFactory().buildGetRequest(tokenUrl);
    JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY);
    request.setParser(parser);
    request.getHeaders().set("Metadata-Flavor", "Google");
    request.setThrowExceptionOnExecuteError(false);
    HttpResponse response;
    try {
      response = request.execute();
    } catch (UnknownHostException exception) {
      throw new IOException("ComputeEngineCredentials cannot find the metadata server. This is"
          + " likely because code is not running on Google Compute Engine.", exception);
    }
    int statusCode = response.getStatusCode();
    if (statusCode == HttpStatusCodes.STATUS_CODE_NOT_FOUND) {
      throw new IOException(String.format("Error code %s trying to get security access token from"
          + " Compute Engine metadata for the default service account. This may be because"
          + " the virtual machine instance does not have permission scopes specified.",
          statusCode));
    }
    if (statusCode != HttpStatusCodes.STATUS_CODE_OK) {
      throw new IOException(String.format("Unexpected Error code %s trying to get security access"
          + " token from Compute Engine metadata for the default service account: %s", statusCode,
          response.parseAsString()));
    }
    InputStream content = response.getContent();
    if (content == null) {
      // Throw explicitly here on empty content to avoid NullPointerException from parseAs call.
      // Mock transports will have success code with empty content by default.
      throw new IOException("Empty content from metadata token server request.");
    }
    GenericData responseData = response.parseAs(GenericData.class);
    String accessToken = OAuth2Utils.validateString(
        responseData, "access_token", PARSE_ERROR_PREFIX);
    int expiresInSeconds = OAuth2Utils.validateInt32(
        responseData, "expires_in", PARSE_ERROR_PREFIX);
    long expiresAtMilliseconds = clock.currentTimeMillis() + expiresInSeconds * 1000;
    return new AccessToken(accessToken, new Date(expiresAtMilliseconds));
  }

  /** Return whether code is running on Google Compute Engine. */
  static boolean runningOnComputeEngine(
      HttpTransportFactory transportFactory, DefaultCredentialsProvider provider) {
    // If the environment has requested that we do no GCE checks, return immediately.
    if (Boolean.parseBoolean(provider.getEnv(DefaultCredentialsProvider.NO_GCE_CHECK_ENV_VAR))) {
      return false;
    }

    GenericUrl tokenUrl = new GenericUrl(getMetadataServerUrl(provider));
    for (int i = 1; i <= MAX_COMPUTE_PING_TRIES; ++i) {
      try {
        HttpRequest request =
            transportFactory.create().createRequestFactory().buildGetRequest(tokenUrl);
        request.setConnectTimeout(COMPUTE_PING_CONNECTION_TIMEOUT_MS);
        HttpResponse response = request.execute();
        try {
          // Internet providers can return a generic response to all requests, so it is necessary
          // to check that metadata header is present also.
          HttpHeaders headers = response.getHeaders();
          return OAuth2Utils.headersContainValue(headers, "Metadata-Flavor", "Google");
        } finally {
          response.disconnect();
        }
      } catch (SocketTimeoutException expected) {
        // Ignore logging timeouts which is the expected failure mode in non GCE environments.
      } catch (IOException e) {
        LOGGER.log(
            Level.WARNING, "Failed to detect whether we are running on Google Compute Engine.", e);
      }
    }
    return false;
  }

  public static String getMetadataServerUrl(DefaultCredentialsProvider provider) {
    String metadataServerAddress = provider.getEnv(DefaultCredentialsProvider.GCE_METADATA_HOST_ENV_VAR);
    if (metadataServerAddress != null) {
      return "http://" + metadataServerAddress;
    }
    return DEFAULT_METADATA_SERVER_URL;
  }

  public static String getMetadataServerUrl() {
    return getMetadataServerUrl(DefaultCredentialsProvider.DEFAULT);
  }

  public static String getTokenServerEncodedUrl(DefaultCredentialsProvider provider) {
    return getMetadataServerUrl(provider) + "/computeMetadata/v1/instance/service-accounts/default/token";
  }

  public static String getTokenServerEncodedUrl() {
    return getTokenServerEncodedUrl(DefaultCredentialsProvider.DEFAULT);
  }

  @Override
  public int hashCode() {
    return Objects.hash(transportFactoryClassName);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("transportFactoryClassName", transportFactoryClassName)
        .toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof ComputeEngineCredentials)) {
      return false;
    }
    ComputeEngineCredentials other = (ComputeEngineCredentials) obj;
    return Objects.equals(this.transportFactoryClassName, other.transportFactoryClassName);
  }

  private void readObject(ObjectInputStream input) throws IOException, ClassNotFoundException {
    input.defaultReadObject();
    transportFactory = newInstance(transportFactoryClassName);
  }

  public Builder toBuilder() {
    return new Builder(this);
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static class Builder extends GoogleCredentials.Builder {
    private HttpTransportFactory transportFactory;

    protected Builder() {}

    protected Builder(ComputeEngineCredentials credentials) {
      this.transportFactory = credentials.transportFactory;
    }

    public Builder setHttpTransportFactory(HttpTransportFactory transportFactory) {
      this.transportFactory = transportFactory;
      return this;
    }

    public HttpTransportFactory getHttpTransportFactory() {
      return transportFactory;
    }

    public ComputeEngineCredentials build() {
      return new ComputeEngineCredentials(transportFactory);
    }
  }
}
