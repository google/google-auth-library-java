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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

import com.google.auth.TestUtils;
import com.google.auth.oauth2.GoogleCredentialsTest.MockTokenServerTransportFactory;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Unit Tests for UserAuthorizer
 */
@RunWith(JUnit4.class)
public class UserAuthorizerTest {
  private static final String CLIENT_ID_VALUE = "ya29.1.AADtN_UtlxN3PuGAxrN2XQnZTVRvDyVWnYq4I6dws";
  private static final String CLIENT_SECRET = "jakuaL9YyieakhECKL2SwZcu";
  private static final String REFRESH_TOKEN = "1/Tl6awhpFjkMkSJoj1xsli0H2eL5YsMgU_NKPY2TyGWY";
  private static final String ACCESS_TOKEN_VALUE = "1/MkSJoj1xsli0AccessToken_NKPY2";
  private static final Long EXPIRATION_TIME = 504000300L;
  private static final AccessToken ACCESS_TOKEN =
      new AccessToken(ACCESS_TOKEN_VALUE, new Date(EXPIRATION_TIME));
  private static final ClientId CLIENT_ID = new ClientId(CLIENT_ID_VALUE, CLIENT_SECRET);
  private static final String SCOPE = "dummy.scope";
  private static final Collection<String> SCOPES = Collections.singletonList(SCOPE);
  private static final String USER_ID = "foo@bar.com";
  private static final URI CALLBACK_URI = URI.create("/testcallback");
  private static final String CODE = "thisistheend";
  private static final URI BASE_URI = URI.create("http://example.com/foo");

  @Test
  public void constructorMinimum() {
    TestTokenStore store = new TestTokenStore();

    UserAuthorizer authorizer = new UserAuthorizer(CLIENT_ID, SCOPES, store);

    assertSame(CLIENT_ID, authorizer.getClientId());
    assertSame(store, authorizer.getTokenStore());
    assertArrayEquals(SCOPES.toArray(), authorizer.getScopes().toArray());
    assertEquals(UserAuthorizer.DEFAULT_CALLBACK_URI, authorizer.getCallbackUri());
  }

  @Test
  public void constructorCommon() {
    TestTokenStore store = new TestTokenStore();

    UserAuthorizer authorizer = new UserAuthorizer(CLIENT_ID, SCOPES, store, CALLBACK_URI);

    assertSame(CLIENT_ID, authorizer.getClientId());
    assertSame(store, authorizer.getTokenStore());
    assertArrayEquals(SCOPES.toArray(), authorizer.getScopes().toArray());
    assertEquals(CALLBACK_URI, authorizer.getCallbackUri());
  }

  @Test(expected = NullPointerException.class)
  public void constructorCommon_nullClientId_throws() {
    new UserAuthorizer(null, SCOPES, null);
  }

  @Test(expected = NullPointerException.class)
  public void constructorCommon_nullScopes_throws() {
    new UserAuthorizer(CLIENT_ID, null, null);
  }

  @Test
  public void getCallbackUri_relativeToBase() {
    final URI callbackURI = URI.create("/bar");
    final URI expectedCallbackURI = URI.create("http://example.com/bar");
    UserAuthorizer authorizer = new UserAuthorizer(CLIENT_ID, SCOPES, null, callbackURI);

    URI absoluteCallbackURI = authorizer.getCallbackUri(BASE_URI);

    assertEquals(expectedCallbackURI, absoluteCallbackURI);
  }

  @Test
  public void getAuthorizationUrl() throws IOException {
    final String CUSTOM_STATE = "custom_state";
    final String PROTOCOL = "https";
    final String HOST = "accounts.test.com";
    final String PATH = "/o/o/oauth2/auth";
    final URI AUTH_URI = URI.create(PROTOCOL + "://" + HOST + PATH);
    final String EXPECTED_CALLBACK = "http://example.com" + CALLBACK_URI.toString();
    UserAuthorizer authorizer = new UserAuthorizer(
        CLIENT_ID, SCOPES, null, CALLBACK_URI, null, null, AUTH_URI);

    URL authorizationUrl = authorizer.getAuthorizationUrl(USER_ID, CUSTOM_STATE, BASE_URI);

    assertEquals(PROTOCOL, authorizationUrl.getProtocol());
    assertEquals(-1, authorizationUrl.getPort());
    assertEquals(PATH, authorizationUrl.getPath());
    assertEquals(HOST, authorizationUrl.getHost());
    String query = authorizationUrl.getQuery();
    Map<String, String> parameters = TestUtils.parseQuery(query);
    assertEquals(CUSTOM_STATE, parameters.get("state"));
    assertEquals(USER_ID, parameters.get("login_hint"));
    assertEquals(EXPECTED_CALLBACK, parameters.get("redirect_uri"));
    assertEquals(CLIENT_ID_VALUE, parameters.get("client_id"));
    assertEquals(SCOPE, parameters.get("scope"));
    assertEquals("code", parameters.get("response_type"));
  }

  @Test
  public void getCredentials_noCredentials_returnsNull() throws IOException {
    UserAuthorizer authorizer = new UserAuthorizer(CLIENT_ID, SCOPES, new TestTokenStore());

    UserCredentials credentials = authorizer.getCredentials(USER_ID);

    assertNull(credentials);
  }

  @Test
  public void getCredentials_storedCredentials_returnsStored() throws IOException {
    TestTokenStore tokenStore = new TestTokenStore();
    UserCredentials initialCredentials =
        new UserCredentials(CLIENT_ID_VALUE, CLIENT_SECRET, REFRESH_TOKEN, ACCESS_TOKEN);
    UserAuthorizer authorizer = new UserAuthorizer(CLIENT_ID, SCOPES, tokenStore);
    authorizer.storeCredentials(USER_ID, initialCredentials);

    UserCredentials credentials = authorizer.getCredentials(USER_ID);

    assertEquals(REFRESH_TOKEN, credentials.getRefreshToken());
    assertEquals(ACCESS_TOKEN_VALUE, credentials.getAccessToken().getTokenValue());
    assertEquals(EXPIRATION_TIME, credentials.getAccessToken().getExpirationTimeMillis());
  }

  @Test(expected = NullPointerException.class)
  public void getCredentials_nullUserId_throws() throws IOException {
    TestTokenStore tokenStore = new TestTokenStore();
    UserAuthorizer authorizer = new UserAuthorizer(CLIENT_ID, SCOPES, tokenStore);

    authorizer.getCredentials(null);
  }

  @Test(expected = IllegalStateException.class)
  public void getCredentials_nullTokenStore_throws() throws IOException {
    UserAuthorizer authorizer = new UserAuthorizer(CLIENT_ID, SCOPES, null);

    authorizer.getCredentials(USER_ID);
  }

  @Test
  public void getCredentials_refreshedToken_stored() throws IOException {
    final String accessTokenValue1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessTokenValue2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    AccessToken acessToken1 =
        new AccessToken(accessTokenValue1, new Date(EXPIRATION_TIME));
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID_VALUE, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessTokenValue2);
    TestTokenStore tokenStore = new TestTokenStore();
    UserAuthorizer authorizer =
        new UserAuthorizer(CLIENT_ID, SCOPES, tokenStore, null, transportFactory, null, null);
    UserCredentials originalCredentials = new UserCredentials(
        CLIENT_ID_VALUE, CLIENT_SECRET, REFRESH_TOKEN, acessToken1, transportFactory, null);
    authorizer.storeCredentials(USER_ID, originalCredentials);

    UserCredentials credentials1 = authorizer.getCredentials(USER_ID);

    assertEquals(REFRESH_TOKEN, credentials1.getRefreshToken());
    assertEquals(accessTokenValue1, credentials1.getAccessToken().getTokenValue());

    // Refresh the token to get update from token server
    credentials1.refresh();
    assertEquals(REFRESH_TOKEN, credentials1.getRefreshToken());
    assertEquals(accessTokenValue2, credentials1.getAccessToken().getTokenValue());

    // Load a second credentials instance
    UserCredentials credentials2 = authorizer.getCredentials(USER_ID);

    // Verify that token refresh stored the updated tokens
    assertEquals(REFRESH_TOKEN, credentials2.getRefreshToken());
    assertEquals(accessTokenValue2, credentials2.getAccessToken().getTokenValue());
  }

  @Test
  public void getCredentialsFromCode_conevertsCodeToTokens() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID_VALUE, CLIENT_SECRET);
    transportFactory.transport.addAuthorizationCode(CODE, REFRESH_TOKEN, ACCESS_TOKEN_VALUE);
    TestTokenStore tokenStore = new TestTokenStore();
    UserAuthorizer authorizer =
        new UserAuthorizer(CLIENT_ID, SCOPES, tokenStore, null, transportFactory, null, null);

    UserCredentials credentials = authorizer.getCredentialsFromCode(CODE, BASE_URI);

    assertEquals(REFRESH_TOKEN, credentials.getRefreshToken());
    assertEquals(ACCESS_TOKEN_VALUE, credentials.getAccessToken().getTokenValue());
  }

  @Test(expected = NullPointerException.class)
  public void getCredentialsFromCode_nullCode_throws() throws IOException {
    UserAuthorizer authorizer =
        new UserAuthorizer(CLIENT_ID, SCOPES, new TestTokenStore());

    authorizer.getCredentialsFromCode(null, BASE_URI);
  }

  @Test
  public void getAndStoreCredentialsFromCode_getAndStoresCredentials() throws IOException {
    final String accessTokenValue1 = "1/MkSJoj1xsli0AccessToken_NKPY2";
    final String accessTokenValue2 = "2/MkSJoj1xsli0AccessToken_NKPY2";
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID_VALUE, CLIENT_SECRET);
    transportFactory.transport.addAuthorizationCode(CODE, REFRESH_TOKEN, accessTokenValue1);
    TestTokenStore tokenStore = new TestTokenStore();
    UserAuthorizer authorizer =
        new UserAuthorizer(CLIENT_ID, SCOPES, tokenStore, null, transportFactory, null, null);

    UserCredentials credentials1 =
        authorizer.getAndStoreCredentialsFromCode(USER_ID, CODE, BASE_URI);

    assertEquals(REFRESH_TOKEN, credentials1.getRefreshToken());
    assertEquals(accessTokenValue1, credentials1.getAccessToken().getTokenValue());

    // Refresh the token to get update from token server
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, accessTokenValue2);
    credentials1.refresh();
    assertEquals(REFRESH_TOKEN, credentials1.getRefreshToken());
    assertEquals(accessTokenValue2, credentials1.getAccessToken().getTokenValue());

    // Load a second credentials instance
    UserCredentials credentials2 = authorizer.getCredentials(USER_ID);

    // Verify that token refresh stored the updated tokens
    assertEquals(REFRESH_TOKEN, credentials2.getRefreshToken());
    assertEquals(accessTokenValue2, credentials2.getAccessToken().getTokenValue());
  }

  @Test(expected = NullPointerException.class)
  public void getAndStoreCredentialsFromCode_nullCode_throws() throws IOException {
    UserAuthorizer authorizer =
        new UserAuthorizer(CLIENT_ID, SCOPES, new TestTokenStore());

    authorizer.getAndStoreCredentialsFromCode(USER_ID, null, BASE_URI);
  }

  @Test(expected = NullPointerException.class)
  public void getAndStoreCredentialsFromCode_nullUserId_throws() throws IOException {
    UserAuthorizer authorizer =
        new UserAuthorizer(CLIENT_ID, SCOPES, new TestTokenStore());

    authorizer.getAndStoreCredentialsFromCode(null, CODE, BASE_URI);
  }

  @Test
  public void revokeAuthorization_revokesAndClears() throws IOException {
    TestTokenStore tokenStore = new TestTokenStore();
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(CLIENT_ID_VALUE, CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, ACCESS_TOKEN_VALUE);
    UserCredentials initialCredentials =
        new UserCredentials(CLIENT_ID_VALUE, CLIENT_SECRET, REFRESH_TOKEN, ACCESS_TOKEN);
    UserAuthorizer authorizer =
        new UserAuthorizer(CLIENT_ID, SCOPES, tokenStore, null, transportFactory, null, null);
    authorizer.storeCredentials(USER_ID, initialCredentials);

    UserCredentials credentials1 = authorizer.getCredentials(USER_ID);

    assertEquals(REFRESH_TOKEN, credentials1.getRefreshToken());
    credentials1.refresh();
    assertEquals(ACCESS_TOKEN_VALUE, credentials1.getAccessToken().getTokenValue());

    authorizer.revokeAuthorization(USER_ID);

    try {
      credentials1.refresh();
      fail("Credentials should not refresh after revoke.");
    } catch (IOException expected) {
      // Expected
    }
    UserCredentials credentials2 = authorizer.getCredentials(USER_ID);
    assertNull(credentials2);
  }

  private static class TestTokenStore implements TokenStore {

    private final Map<String, String> map = new HashMap<>();

    @Override
    public String load(String id) throws IOException {
      return map.get(id);
    }

    @Override
    public void store(String id, String tokens) throws IOException {
      map.put(id, tokens);
    }

    @Override
    public void delete(String id) throws IOException {
      map.remove(id);
    }
  }
}
