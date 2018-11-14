/*
 * Copyright 2018, Google Inc. All rights reserved.
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

import java.io.IOException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpContent;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.GenericData;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.http.HttpTransportFactory;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableMap;

/**
 * ImpersonatedCredentials allowing credentials issued to a user or
 * service account to impersonate another.
 * <br/>
 * The source project using ImpersonatedCredentials must enable the
 * "IAMCredentials" API.<br/>
 * Also, the target service account must grant the orginating principal the
 * "Service Account Token Creator" IAM role.
 * <br/>
 * Usage:<br/>
 * <pre>
 * String credPath = "/path/to/svc_account.json";
 * ServiceAccountCredentials sourceCredentials = ServiceAccountCredentials
 *     .fromStream(new FileInputStream(credPath));
 * sourceCredentials = (ServiceAccountCredentials) sourceCredentials
 *     .createScoped(Arrays.asList("https://www.googleapis.com/auth/iam"));
 *
 * ImpersonatedCredentials targetCredentials = ImpersonatedCredentials.create(sourceCredentials,
 *     "impersonated-account@project.iam.gserviceaccount.com", null,
 *     Arrays.asList("https://www.googleapis.com/auth/devstorage.read_only"), 300);
 *
 * Storage storage_service = StorageOptions.newBuilder().setProjectId("project-id")
 *    .setCredentials(targetCredentials).build().getService();
 *
 * for (Bucket b : storage_service.list().iterateAll())
 *     System.out.println(b);
 * </pre>
 */
public class ImpersonatedCredentials extends GoogleCredentials {

  private static final long serialVersionUID = -2133257318957488431L;
  private static final String RFC3339 = "yyyy-MM-dd'T'HH:mm:ss'Z'";
  private static final int ONE_HOUR_IN_SECONDS = 3600;
  private static final String CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform";
  private static final String ERROR_PREFIX = "Error processng IamCredentials generateAccessToken: ";
  private static final String IAM_ENDPOINT = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken";

  private static final String SCOPE_EMPTY_ERROR = "Scopes cannot be null";
  private static final String LIFETIME_EXCEEDED_ERROR = "lifetime must be less than or equal to 3600";

  private GoogleCredentials sourceCredentials;
  private String targetPrincipal;
  private List<String> delegates;
  private List<String> scopes;
  private int lifetime;
  private final String transportFactoryClassName;

  private transient HttpTransportFactory transportFactory;

  /**
   * @param sourceCredentials The source credential used as to acquire the
   * impersonated credentials
   * @param targetPrincipal   The service account to impersonate.
   * @param delegates         The chained list of delegates required to grant
   * the final access_token.  <br/>If set, the sequence of identities must
   * have "Service Account Token Creator" capability granted to the
   * prceeding identity.  <br/>For example, if set to
   * [serviceAccountB, serviceAccountC], the sourceCredential
   * must have the Token Creator role on serviceAccountB. serviceAccountB must
   * have the Token Creator on serviceAccountC.  <br/>Finally, C must have
   * Token Creator on target_principal. If left unset, sourceCredential
   * must have that role on targetPrincipal.
   * @param scopes            Scopes to request during the authorization grant.
   * @param lifetime          Number of seconds the delegated credential should
   * be valid for (upto 3600).
   * @param transportFactory  HTTP transport factory, creates the transport used
   *                          to get access tokens.
   */
  public static ImpersonatedCredentials create(GoogleCredentials sourceCredentials, String targetPrincipal,
      List<String> delegates, List<String> scopes, int lifetime, HttpTransportFactory transportFactory) {
    return ImpersonatedCredentials.newBuilder().setSourceCredentials(sourceCredentials)
        .setTargetPrincipal(targetPrincipal).setDelegates(delegates).setScopes(scopes).setLifetime(lifetime)
        .setHttpTransportFactory(transportFactory).build();
  }

  /**
   * @param sourceCredentials The source credential used as to acquire the
   * impersonated credentials
   * @param targetPrincipal   The service account to impersonate.
   * @param delegates         The chained list of delegates required to grant
   * the final access_token.  <br/>If set, the sequence of identities must
   * have "Service Account Token Creator" capability granted to the
   * prceeding identity.  <br/>For example, if set to
   * [serviceAccountB, serviceAccountC], the sourceCredential
   * must have the Token Creator role on serviceAccountB. serviceAccountB must
   * have the Token Creator on serviceAccountC.  <br/>Finally, C must have
   * Token Creator on target_principal. If left unset, sourceCredential
   * must have that role on targetPrincipal.
   * @param scopes            Scopes to request during the authorization grant.
   * @param lifetime          Number of seconds the delegated credential should
   * be valid for (upto 3600).
   */ 
  public static ImpersonatedCredentials create(GoogleCredentials sourceCredentials, String targetPrincipal,
      List<String> delegates, List<String> scopes, int lifetime) {
    return ImpersonatedCredentials.newBuilder().setSourceCredentials(sourceCredentials)
        .setTargetPrincipal(targetPrincipal).setDelegates(delegates).setScopes(scopes).setLifetime(lifetime).build();
  }

  /**
   * @param sourceCredentials = Source Credentials.
   * @param targetPrincipal   = targetPrincipal;
   * @param delegates         = delegates;
   * @param scopes            = scopes;
   * @param lifetime          = lifetime;
   * @param transportFactory  = HTTP transport factory, creates the transport used
   *                          to get access tokens.
   * @deprecated Use {@link #create(ImpersonatedCredentials)} instead. This constructor
   *             will either be deleted or made private in a later version.
   */
  @Deprecated
  private ImpersonatedCredentials(GoogleCredentials sourceCredentials, String targetPrincipal, List<String> delegates,
      List<String> scopes, int lifetime, HttpTransportFactory transportFactory) {
    this.sourceCredentials = sourceCredentials;
    this.targetPrincipal = targetPrincipal;
    this.delegates = delegates;
    this.scopes = scopes;
    this.lifetime = lifetime;
    this.transportFactory = firstNonNull(transportFactory,
        getFromServiceLoader(HttpTransportFactory.class, OAuth2Utils.HTTP_TRANSPORT_FACTORY));
    this.transportFactoryClassName = this.transportFactory.getClass().getName();
    if (this.delegates == null) {
      this.delegates = new ArrayList<String>();
    }
    if (this.scopes == null) {
      throw new IllegalStateException(SCOPE_EMPTY_ERROR);
    }
    if (this.lifetime > ONE_HOUR_IN_SECONDS) {
      throw new IllegalStateException(LIFETIME_EXCEEDED_ERROR);
    }
  }

  /**
   * @param sourceCredentials = Source Credentials.
   * @param targetPrincipal   = targetPrincipal;
   * @param scopes            = scopes;
   * @param lifetime          = lifetime;
   * @param transportFactory  = HTTP transport factory, creates the transport used
   *                          to get access tokens.
   * @deprecated Use {@link #create(ImpersonatedCredentials)} instead. This constructor
   *             will either be deleted or made private in a later version.
   */
  @Deprecated
  private ImpersonatedCredentials(GoogleCredentials sourceCredentials, String targetPrincipal, List<String> scopes,
      int lifetime, HttpTransportFactory transportFactory) {
    this(sourceCredentials, targetPrincipal, new ArrayList<String>(), scopes, lifetime, transportFactory);
  }

  /**
   * @param sourceCredentials = Source Credentials.
   * @param targetPrincipal   = targetPrincipal;
   * @param delegates         = delegates;
   * @param scopes            = scopes;
   * @param lifetime          = lifetime;
   * @deprecated Use {@link #create(ImpersonatedCredentials)} instead. This constructor
   *             will either be deleted or made private in a later version.
   */
  @Deprecated
  private ImpersonatedCredentials(GoogleCredentials sourceCredentials, String targetPrincipal, List<String> scopes,
      int lifetime) {
    this(sourceCredentials, targetPrincipal, new ArrayList<String>(), scopes, lifetime, null);
  }

  @Override
  public AccessToken refreshAccessToken() throws IOException {
    
    try {
      if (this.sourceCredentials.getAccessToken() == null) {
        this.sourceCredentials = this.sourceCredentials.createScoped(Arrays.asList(CLOUD_PLATFORM_SCOPE));
      }
      this.sourceCredentials.refreshIfExpired();
    } catch (IOException e) {
      throw new IOException(ERROR_PREFIX + "Unable to refresh sourceCredentials " + e.toString());
    }

    HttpTransport httpTransport = this.transportFactory.create();
    JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY);

    HttpCredentialsAdapter adapter = new HttpCredentialsAdapter(sourceCredentials);
    HttpRequestFactory requestFactory = httpTransport.createRequestFactory();

    String endpointUrl = String.format(IAM_ENDPOINT, this.targetPrincipal);
    GenericUrl url = new GenericUrl(endpointUrl);

    Map<String, Object> body = ImmutableMap.<String, Object>of("delegates", this.delegates, "scope", this.scopes,
        "lifetime", this.lifetime + "s");

    HttpContent requestContent = new JsonHttpContent(parser.getJsonFactory(), body);
    HttpRequest request = requestFactory.buildPostRequest(url, requestContent);
    adapter.initialize(request);
    request.setParser(parser);

    HttpResponse response = null;
    try {
      response = request.execute();
    } catch (IOException e) {
      throw new IOException(ERROR_PREFIX + e.toString());
    }

    GenericData responseData = response.parseAs(GenericData.class);
    response.disconnect();

    String accessToken = OAuth2Utils.validateString(responseData, "accessToken", ERROR_PREFIX);
    String expireTime = OAuth2Utils.validateString(responseData, "expireTime", ERROR_PREFIX);

    DateFormat format = new SimpleDateFormat(RFC3339);
    Date date;
    try {
      date = format.parse(expireTime);
    } catch (ParseException pe) {
      throw new IOException(ERROR_PREFIX + pe.getMessage());
    }
    return new AccessToken(accessToken, date);
  }


  @Override
  public int hashCode() {
    return Objects.hash(sourceCredentials, targetPrincipal, delegates, scopes, lifetime);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("sourceCredentials", sourceCredentials)
        .add("targetPrincipal", targetPrincipal)
        .add("delegates", delegates)
        .add("scopes", scopes)
        .add("lifetime", lifetime)
        .add("transportFactoryClassName", transportFactoryClassName).toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof ImpersonatedCredentials)) {
      return false;
    }
    ImpersonatedCredentials other = (ImpersonatedCredentials) obj;
    return Objects.equals(this.sourceCredentials, other.sourceCredentials)
        && Objects.equals(this.targetPrincipal, other.targetPrincipal)
        && Objects.equals(this.delegates, other.delegates)
        && Objects.equals(this.scopes, other.scopes)
        && Objects.equals(this.lifetime, other.lifetime)
        && Objects.equals(this.transportFactoryClassName, other.transportFactoryClassName);
  }

  public Builder toBuilder() {
    return new Builder(this.sourceCredentials, this.targetPrincipal);
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static class Builder extends GoogleCredentials.Builder {

    private GoogleCredentials sourceCredentials;
    private String targetPrincipal;
    private List<String> delegates;
    private List<String> scopes;
    private int lifetime;
    private HttpTransportFactory transportFactory;

    protected Builder() {
    }

    protected Builder(GoogleCredentials sourceCredentials, String targetPrincipal) {
      this.sourceCredentials = sourceCredentials;
      this.targetPrincipal = targetPrincipal;
    }

    public Builder setSourceCredentials(GoogleCredentials sourceCredentials) {
      this.sourceCredentials = sourceCredentials;
      return this;
    }

    public GoogleCredentials getSourceCredentials() {
      return this.sourceCredentials;
    }

    public Builder setTargetPrincipal(String targetPrincipal) {
      this.targetPrincipal = targetPrincipal;
      return this;
    }

    public String getTargetPrincipal() {
      return this.targetPrincipal;
    }

    public Builder setDelegates(List<String> delegates) {
      this.delegates = delegates;
      return this;
    }

    public List<String> getDelegates() {
      return this.delegates;
    }

    public Builder setScopes(List<String> scopes) {
      this.scopes = scopes;
      return this;
    }

    public List<String> getScopes() {
      return this.scopes;
    }

    public Builder setLifetime(int lifetime) {
      this.lifetime = lifetime;
      return this;
    }

    public int getLifetime() {
      return this.lifetime;
    }

    public Builder setHttpTransportFactory(HttpTransportFactory transportFactory) {
      this.transportFactory = transportFactory;
      return this;
    }

    public HttpTransportFactory getHttpTransportFactory() {
      return transportFactory;
    }

    public ImpersonatedCredentials build() {
      return new ImpersonatedCredentials(this.sourceCredentials, this.targetPrincipal, this.delegates, this.scopes,
          this.lifetime, this.transportFactory);
    }

  }
}