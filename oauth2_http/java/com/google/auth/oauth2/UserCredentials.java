package com.google.auth.oauth2;

import static com.google.common.base.MoreObjects.firstNonNull;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.UrlEncodedContent;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.GenericData;
import com.google.api.client.util.Preconditions;
import com.google.auth.http.HttpTransportFactory;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.URI;
import java.util.Date;
import java.util.Map;
import java.util.Objects;

/**
 * OAuth2 Credentials representing a user's identity and consent.
 */
public class UserCredentials extends GoogleCredentials {

  private static final String GRANT_TYPE = "refresh_token";
  private static final String PARSE_ERROR_PREFIX = "Error parsing token refresh response. ";
  private static final long serialVersionUID = -4800758775038679176L;

  private final String clientId;
  private final String clientSecret;
  private final String refreshToken;
  private final URI tokenServerUri;
  private final String transportFactoryClassName;

  private transient HttpTransportFactory transportFactory;

  /**
   * Constructor with minimum information and default behavior.
   *
   * @param clientId Client ID of the credential from the console.
   * @param clientSecret Client ID of the credential from the console.
   * @param refreshToken A refresh token resulting from a OAuth2 consent flow.
   */
  public UserCredentials(String clientId, String clientSecret, String refreshToken) {
    this(clientId, clientSecret, refreshToken, null, null, null);
  }

  /**
   * Constructor to allow both refresh token and initial access token for 3LO scenarios.
   *
   * @param clientId Client ID of the credential from the console.
   * @param clientSecret Client ID of the credential from the console.
   * @param refreshToken A refresh token resulting from a OAuth2 consent flow.
   * @param accessToken Initial or temporary access token.
   */
  public UserCredentials(
      String clientId, String clientSecret, String refreshToken, AccessToken accessToken) {
    this(clientId, clientSecret, refreshToken, accessToken, null, null);
  }


  /**
   * Constructor with all parameters allowing custom transport and server URL.
   *
   * @param clientId Client ID of the credential from the console.
   * @param clientSecret Client ID of the credential from the console.
   * @param refreshToken A refresh token resulting from a OAuth2 consent flow.
   * @param accessToken Initial or temporary access token.
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *        tokens.
   * @param tokenServerUri URI of the end point that provides tokens.
   */
  public UserCredentials(String clientId, String clientSecret, String refreshToken,
      AccessToken accessToken, HttpTransportFactory transportFactory, URI tokenServerUri) {
    super(accessToken);
    this.clientId = Preconditions.checkNotNull(clientId);
    this.clientSecret = Preconditions.checkNotNull(clientSecret);
    this.refreshToken = refreshToken;
    this.transportFactory = firstNonNull(transportFactory,
        getFromServiceLoader(HttpTransportFactory.class, OAuth2Utils.HTTP_TRANSPORT_FACTORY));
    this.tokenServerUri = (tokenServerUri == null) ? OAuth2Utils.TOKEN_SERVER_URI : tokenServerUri;
    this.transportFactoryClassName = this.transportFactory.getClass().getName();
    Preconditions.checkState(accessToken != null || refreshToken != null,
        "Either accessToken or refreshToken must not be null");
  }

  /**
   * Returns user crentials defined by JSON contents using the format supported by the Cloud SDK.
   *
   * @param json a map from the JSON representing the credentials.
   * @param transportFactory HTTP transport factory, creates the transport used to get access
   *        tokens.
   * @return the credentials defined by the JSON.
   * @throws IOException if the credential cannot be created from the JSON.
   **/
  static UserCredentials fromJson(Map<String, Object> json, HttpTransportFactory transportFactory)
      throws IOException {
    String clientId = (String) json.get("client_id");
    String clientSecret = (String) json.get("client_secret");
    String refreshToken = (String) json.get("refresh_token");
    if (clientId == null || clientSecret == null || refreshToken == null) {
      throw new IOException("Error reading user credential from JSON, "
          + " expecting 'client_id', 'client_secret' and 'refresh_token'.");
    }
    return new UserCredentials(clientId, clientSecret, refreshToken, null, transportFactory, null);
  }

  /**
   * Refreshes the OAuth2 access token by getting a new access token from the refresh token
   */
  @Override
  public AccessToken refreshAccessToken() throws IOException {
    if (refreshToken ==  null) {
      throw new IllegalStateException("UserCredentials instance cannot refresh because there is no"
          + " refresh token.");
    }
    GenericData tokenRequest = new GenericData();
    tokenRequest.set("client_id", clientId);
    tokenRequest.set("client_secret", clientSecret);
    tokenRequest.set("refresh_token", refreshToken);
    tokenRequest.set("grant_type", GRANT_TYPE);
    UrlEncodedContent content = new UrlEncodedContent(tokenRequest);

    HttpRequestFactory requestFactory = transportFactory.create().createRequestFactory();
    HttpRequest request =
        requestFactory.buildPostRequest(new GenericUrl(tokenServerUri), content);
    request.setParser(new JsonObjectParser(OAuth2Utils.JSON_FACTORY));
    HttpResponse response = request.execute();
    GenericData responseData = response.parseAs(GenericData.class);
    String accessToken =
        OAuth2Utils.validateString(responseData, "access_token", PARSE_ERROR_PREFIX);
    int expiresInSeconds =
        OAuth2Utils.validateInt32(responseData, "expires_in", PARSE_ERROR_PREFIX);
    long expiresAtMilliseconds = clock.currentTimeMillis() + expiresInSeconds * 1000;
    return new AccessToken(accessToken, new Date(expiresAtMilliseconds));
  }

  /**
   * Returns client ID of the credential from the console.
   *
   * @return client ID
   */
  public final String getClientId() {
    return clientId;
  }

  /**
   * Returns client secret of the credential from the console.
   *
   * @return client secret
   */
  public final String getClientSecret() {
    return clientSecret;
  }

  /**
   * Returns the refresh token resulting from a OAuth2 consent flow.
   *
   * @return refresh token
   */
  public final String getRefreshToken() {
    return refreshToken;
  }

  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), clientId, clientSecret, refreshToken, tokenServerUri,
        transportFactoryClassName);
  }

  @Override
  public String toString() {
    return toStringHelper()
        .add("clientId", clientId)
        .add("refreshToken", refreshToken)
        .add("tokenServerUri", tokenServerUri)
        .add("transportFactoryClassName", transportFactoryClassName)
        .toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof UserCredentials)) {
      return false;
    }
    UserCredentials other = (UserCredentials) obj;
    return super.equals(other)
        && Objects.equals(this.clientId, other.clientId)
        && Objects.equals(this.clientSecret, other.clientSecret)
        && Objects.equals(this.refreshToken, other.refreshToken)
        && Objects.equals(this.tokenServerUri, other.tokenServerUri)
        && Objects.equals(this.transportFactoryClassName, other.transportFactoryClassName);
  }

  private void readObject(ObjectInputStream input) throws IOException, ClassNotFoundException {
    input.defaultReadObject();
    transportFactory = newInstance(transportFactoryClassName);
  }
}
