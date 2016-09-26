package com.google.auth.oauth2;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.auth.TestUtils;
import com.google.auth.http.HttpTransportFactory;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Test case for {@link GoogleCredentials}.
 */
@RunWith(JUnit4.class)
public class GoogleCredentialsTest {

  private final static String SA_CLIENT_EMAIL =
      "36680232662-vrd7ji19qe3nelgchd0ah2csanun6bnr@developer.gserviceaccount.com";
  private final static String SA_CLIENT_ID =
      "36680232662-vrd7ji19qe3nelgchd0ah2csanun6bnr.apps.googleusercontent.com";
  private final static String SA_PRIVATE_KEY_ID =
      "d84a4fefcf50791d4a90f2d7af17469d6282df9d";
  private final static String SA_PRIVATE_KEY_PKCS8
      = ServiceAccountCredentialsTest.SA_PRIVATE_KEY_PKCS8;
  private static final String USER_CLIENT_SECRET = "jakuaL9YyieakhECKL2SwZcu";
  private static final String USER_CLIENT_ID = "ya29.1.AADtN_UtlxN3PuGAxrN2XQnZTVRvDyVWnYq4I6dws";
  private static final String REFRESH_TOKEN = "1/Tl6awhpFjkMkSJoj1xsli0H2eL5YsMgU_NKPY2TyGWY";
  private static final String ACCESS_TOKEN = "1/MkSJoj1xsli0AccessToken_NKPY2";
  private static final HttpTransportFactory DUMMY_TRANSPORT_FACTORY =
      new MockTokenServerTransportFactory();
  private static final URI CALL_URI = URI.create("http://googleapis.com/testapi/v1/foo");

  private static final Collection<String> SCOPES =
    Collections.unmodifiableCollection(Arrays.asList("scope1", "scope2"));

  static class MockHttpTransportFactory implements HttpTransportFactory {

    MockHttpTransport transport = new MockHttpTransport();

    @Override
    public HttpTransport create() {
      return transport;
    }
  }

  public static class MockTokenServerTransportFactory implements HttpTransportFactory {

    public MockTokenServerTransport transport = new MockTokenServerTransport();

    @Override
    public HttpTransport create() {
      return transport;
    }
  }

  @Test
  public void getApplicationDefault_nullTransport_throws() throws IOException {
    try {
      GoogleCredentials.getApplicationDefault(null);
      fail();
    } catch (NullPointerException expected) {
    }
  }

  @Test
  public void fromStream_nullTransport_throws() throws IOException {
    InputStream stream = new ByteArrayInputStream("foo".getBytes());
    try {
      GoogleCredentials.fromStream(stream, null);
      fail();
    } catch (NullPointerException expected) {
    }
  }

  @Test
  public void fromStream_nullStreamThrows() throws IOException {
    MockHttpTransportFactory transportFactory = new MockHttpTransportFactory();
    try {
      GoogleCredentials.fromStream(null, transportFactory);
      fail();
    } catch (NullPointerException expected) {
    }
  }

  @Test
  public void fromStream_serviceAccount_providesToken() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);
    InputStream serviceAccountStream = ServiceAccountCredentialsTest
        .writeServiceAccountAccountStream(
            SA_CLIENT_ID, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID);

    GoogleCredentials credentials =
        GoogleCredentials.fromStream(serviceAccountStream, transportFactory);

    assertNotNull(credentials);
    credentials = credentials.createScoped(SCOPES);
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void fromStream_serviceAccountNoClientId_throws() throws IOException {
    InputStream serviceAccountStream = ServiceAccountCredentialsTest
        .writeServiceAccountAccountStream(
            null, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID);

    testFromStreamException(serviceAccountStream, "client_id");
  }

  @Test
  public void fromStream_serviceAccountNoClientEmail_throws() throws IOException {
    InputStream serviceAccountStream = ServiceAccountCredentialsTest
        .writeServiceAccountAccountStream(
            SA_CLIENT_ID, null, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID);

    testFromStreamException(serviceAccountStream, "client_email");
  }

  @Test
  public void fromStream_serviceAccountNoPrivateKey_throws() throws IOException {
    InputStream serviceAccountStream = ServiceAccountCredentialsTest
        .writeServiceAccountAccountStream(
            SA_CLIENT_ID, SA_CLIENT_EMAIL, null, SA_PRIVATE_KEY_ID);

    testFromStreamException(serviceAccountStream, "private_key");
  }

  @Test
  public void fromStream_serviceAccountNoPrivateKeyId_throws() throws IOException {
    InputStream serviceAccountStream = ServiceAccountCredentialsTest
        .writeServiceAccountAccountStream(
            SA_CLIENT_ID, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, null);

    testFromStreamException(serviceAccountStream, "private_key_id");
  }

  @Test
  public void fromStream_user_providesToken() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addClient(USER_CLIENT_ID, USER_CLIENT_SECRET);
    transportFactory.transport.addRefreshToken(REFRESH_TOKEN, ACCESS_TOKEN);
    InputStream userStream =
        UserCredentialsTest.writeUserStream(USER_CLIENT_ID, USER_CLIENT_SECRET, REFRESH_TOKEN);

    GoogleCredentials credentials = GoogleCredentials.fromStream(userStream, transportFactory);

    assertNotNull(credentials);
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void fromStream_userNoClientId_throws() throws IOException {
    InputStream userStream =
        UserCredentialsTest.writeUserStream(null, USER_CLIENT_SECRET, REFRESH_TOKEN);

    testFromStreamException(userStream, "client_id");
  }

  @Test
  public void fromStream_userNoClientSecret_throws() throws IOException {
    InputStream userStream =
        UserCredentialsTest.writeUserStream(USER_CLIENT_ID, null, REFRESH_TOKEN);

    testFromStreamException(userStream, "client_secret");
  }

  @Test
  public void fromStream_userNoRefreshToken_throws() throws IOException {
    InputStream userStream =
        UserCredentialsTest.writeUserStream(USER_CLIENT_ID, USER_CLIENT_SECRET, null);

    testFromStreamException(userStream, "refresh_token");
  }

  private void testFromStreamException(InputStream stream, String expectedMessageContent) {
    try {
      GoogleCredentials.fromStream(stream, DUMMY_TRANSPORT_FACTORY);
      fail();
    } catch (IOException expected) {
      assertTrue(expected.getMessage().contains(expectedMessageContent));
    }
  }
}
