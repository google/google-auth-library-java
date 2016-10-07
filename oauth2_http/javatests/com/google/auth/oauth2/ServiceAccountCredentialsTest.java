package com.google.auth.oauth2;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.api.client.json.GenericJson;
import com.google.api.client.util.Clock;
import com.google.auth.TestUtils;
import com.google.auth.oauth2.GoogleCredentialsTest.MockHttpTransportFactory;
import com.google.auth.oauth2.GoogleCredentialsTest.MockTokenServerTransportFactory;
import com.google.common.collect.ImmutableSet;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Test case for {@link ServiceAccountCredentials}.
 */
@RunWith(JUnit4.class)
public class ServiceAccountCredentialsTest extends BaseSerializationTest {

  private final static String SA_CLIENT_EMAIL =
      "36680232662-vrd7ji19qe3nelgchd0ah2csanun6bnr@developer.gserviceaccount.com";
  private final static String SA_CLIENT_ID =
      "36680232662-vrd7ji19qe3nelgchd0ah2csanun6bnr.apps.googleusercontent.com";
  private final static String SA_PRIVATE_KEY_ID =
      "d84a4fefcf50791d4a90f2d7af17469d6282df9d";
  static final String SA_PRIVATE_KEY_PKCS8 = "-----BEGIN PRIVATE KEY-----\n"
      + "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALX0PQoe1igW12i"
      + "kv1bN/r9lN749y2ijmbc/mFHPyS3hNTyOCjDvBbXYbDhQJzWVUikh4mvGBA07qTj79Xc3yBDfKP2IeyYQIFe0t0"
      + "zkd7R9Zdn98Y2rIQC47aAbDfubtkU1U72t4zL11kHvoa0/RuFZjncvlr42X7be7lYh4p3NAgMBAAECgYASk5wDw"
      + "4Az2ZkmeuN6Fk/y9H+Lcb2pskJIXjrL533vrDWGOC48LrsThMQPv8cxBky8HFSEklPpkfTF95tpD43iVwJRB/Gr"
      + "CtGTw65IfJ4/tI09h6zGc4yqvIo1cHX/LQ+SxKLGyir/dQM925rGt/VojxY5ryJR7GLbCzxPnJm/oQJBANwOCO6"
      + "D2hy1LQYJhXh7O+RLtA/tSnT1xyMQsGT+uUCMiKS2bSKx2wxo9k7h3OegNJIu1q6nZ6AbxDK8H3+d0dUCQQDTrP"
      + "SXagBxzp8PecbaCHjzNRSQE2in81qYnrAFNB4o3DpHyMMY6s5ALLeHKscEWnqP8Ur6X4PvzZecCWU9BKAZAkAut"
      + "LPknAuxSCsUOvUfS1i87ex77Ot+w6POp34pEX+UWb+u5iFn2cQacDTHLV1LtE80L8jVLSbrbrlH43H0DjU5AkEA"
      + "gidhycxS86dxpEljnOMCw8CKoUBd5I880IUahEiUltk7OLJYS/Ts1wbn3kPOVX3wyJs8WBDtBkFrDHW2ezth2QJ"
      + "ADj3e1YhMVdjJW5jqwlD/VNddGjgzyunmiZg0uOXsHXbytYmsA545S8KRQFaJKFXYYFo2kOjqOiC1T2cAzMDjCQ"
      + "==\n-----END PRIVATE KEY-----\n";
  private static final String ACCESS_TOKEN = "1/MkSJoj1xsli0AccessToken_NKPY2";
  private final static Collection<String> SCOPES = Collections.singletonList("dummy.scope");
  private final static Collection<String> EMPTY_SCOPES = Collections.emptyList();
  private static final URI CALL_URI = URI.create("http://googleapis.com/testapi/v1/foo");

  @Test
  public void createdScoped_clones() throws IOException {
    PrivateKey privateKey = ServiceAccountCredentials.privateKeyFromPkcs8(SA_PRIVATE_KEY_PKCS8);
    GoogleCredentials credentials = new ServiceAccountCredentials(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, privateKey, SA_PRIVATE_KEY_ID, null);
    List<String> newScopes = Arrays.asList("scope1", "scope2");

    ServiceAccountCredentials newCredentials =
        (ServiceAccountCredentials) credentials.createScoped(newScopes);

    assertEquals(SA_CLIENT_ID, newCredentials.getClientId());
    assertEquals(SA_CLIENT_EMAIL, newCredentials.getClientEmail());
    assertEquals(privateKey, newCredentials.getPrivateKey());
    assertEquals(SA_PRIVATE_KEY_ID, newCredentials.getPrivateKeyId());
    assertArrayEquals(newScopes.toArray(), newCredentials.getScopes().toArray());
  }

  @Test
  public void createdScoped_enablesAccessTokens() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);
    GoogleCredentials credentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID,
        SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, null, transportFactory, null);

    try {
      credentials.getRequestMetadata(CALL_URI);
      fail("Should not be able to get token without scopes");
    } catch (Exception expected) {
      // Expected
    }

    GoogleCredentials scopedCredentials = credentials.createScoped(SCOPES);

    Map<String, List<String>> metadata = scopedCredentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void createScopedRequired_emptyScopes_true() throws IOException {
    GoogleCredentials credentials = ServiceAccountCredentials.fromPkcs8(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, EMPTY_SCOPES);

    assertTrue(credentials.createScopedRequired());
  }

  @Test
  public void createScopedRequired_nonEmptyScopes_false() throws IOException {
    GoogleCredentials credentials = ServiceAccountCredentials.fromPkcs8(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, SCOPES);

    assertFalse(credentials.createScopedRequired());
  }

  @Test
  public void fromJSON_hasAccessToken() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);
    GenericJson json = writeServiceAccountJson(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID);

    GoogleCredentials credentials = ServiceAccountCredentials.fromJson(json, transportFactory);

    credentials = credentials.createScoped(SCOPES);
    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);
    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void getRequestMetadata_hasAccessToken() throws IOException {
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);
    OAuth2Credentials credentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID,
        SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, SCOPES, transportFactory, null);

    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);

    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void getRequestMetadata_customTokenServer_hasAccessToken() throws IOException {
    final URI TOKEN_SERVER = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    transportFactory.transport.addServiceAccount(SA_CLIENT_EMAIL, ACCESS_TOKEN);
    transportFactory.transport.setTokenServerUri(TOKEN_SERVER);
    OAuth2Credentials credentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID,
        SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, SCOPES, transportFactory,
        TOKEN_SERVER);

    Map<String, List<String>> metadata = credentials.getRequestMetadata(CALL_URI);

    TestUtils.assertContainsBearerToken(metadata, ACCESS_TOKEN);
  }

  @Test
  public void getScopes_nullReturnsEmpty() throws IOException {
    ServiceAccountCredentials credentials = ServiceAccountCredentials.fromPkcs8(
        SA_CLIENT_ID, SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, null);

    Collection<String> scopes = credentials.getScopes();

    assertNotNull(scopes);
    assertTrue(scopes.isEmpty());
  }

  @Test
  public void equals_true() throws IOException {
    final URI tokenServer = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    OAuth2Credentials credentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID,
        SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, SCOPES, transportFactory,
        tokenServer);
    OAuth2Credentials otherCredentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID,
        SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, SCOPES, transportFactory,
        tokenServer);
    assertTrue(credentials.equals(otherCredentials));
    assertTrue(otherCredentials.equals(credentials));
  }

  @Test
  public void equals_false() throws IOException {
    final URI tokenServer1 = URI.create("https://foo1.com/bar");
    final URI tokenServer2 = URI.create("https://foo2.com/bar");
    MockHttpTransportFactory httpTransportFactory = new MockHttpTransportFactory();
    MockTokenServerTransportFactory serverTransportFactory = new MockTokenServerTransportFactory();
    OAuth2Credentials credentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID,
        SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, SCOPES, serverTransportFactory,
        tokenServer1);
    OAuth2Credentials otherCredentials = ServiceAccountCredentials.fromPkcs8("otherClientId",
        SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, SCOPES, serverTransportFactory,
        tokenServer1);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
    otherCredentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID, "otherEmail",
        SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, SCOPES, serverTransportFactory, tokenServer1);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
    otherCredentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID, SA_CLIENT_EMAIL,
        SA_PRIVATE_KEY_PKCS8, "otherId", SCOPES, serverTransportFactory, tokenServer1);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
    otherCredentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID, SA_CLIENT_EMAIL,
        SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, ImmutableSet.<String>of(), serverTransportFactory,
        tokenServer1);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
    otherCredentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID, SA_CLIENT_EMAIL,
        SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, SCOPES, httpTransportFactory, tokenServer1);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
    otherCredentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID, SA_CLIENT_EMAIL,
        SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, SCOPES, serverTransportFactory, tokenServer2);
    assertFalse(credentials.equals(otherCredentials));
    assertFalse(otherCredentials.equals(credentials));
  }

  @Test
  public void toString_containsFields() throws IOException {
    final URI tokenServer = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    OAuth2Credentials credentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID,
        SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, SCOPES, transportFactory,
        tokenServer);
    String expectedToString = String.format(
        "ServiceAccountCredentials{clientId=%s, clientEmail=%s, privateKeyId=%s, "
            + "transportFactoryClassName=%s, tokenServerUri=%s, scopes=%s}",
        SA_CLIENT_ID,
        SA_CLIENT_EMAIL,
        SA_PRIVATE_KEY_ID,
        MockTokenServerTransportFactory.class.getName(),
        tokenServer,
        SCOPES);
    assertEquals(expectedToString, credentials.toString());
  }

  @Test
  public void hashCode_equals() throws IOException {
    final URI tokenServer = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    OAuth2Credentials credentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID,
        SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, SCOPES, transportFactory,
        tokenServer);
    OAuth2Credentials otherCredentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID,
        SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, SCOPES, transportFactory,
        tokenServer);
    assertEquals(credentials.hashCode(), otherCredentials.hashCode());
  }

  @Test
  public void hashCode_notEquals() throws IOException {
    final URI tokenServer1 = URI.create("https://foo1.com/bar");
    final URI tokenServer2 = URI.create("https://foo2.com/bar");
    MockHttpTransportFactory httpTransportFactory = new MockHttpTransportFactory();
    MockTokenServerTransportFactory serverTransportFactory = new MockTokenServerTransportFactory();
    OAuth2Credentials credentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID,
        SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, SCOPES, serverTransportFactory,
        tokenServer1);
    OAuth2Credentials otherCredentials = ServiceAccountCredentials.fromPkcs8("otherClientId",
        SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, SCOPES, serverTransportFactory,
        tokenServer1);
    assertFalse(credentials.hashCode() == otherCredentials.hashCode());
    otherCredentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID, "otherEmail",
        SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, SCOPES, serverTransportFactory, tokenServer1);
    assertFalse(credentials.hashCode() == otherCredentials.hashCode());
    otherCredentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID, "otherEmail",
        SA_PRIVATE_KEY_PKCS8, "otherId", SCOPES, serverTransportFactory, tokenServer1);
    assertFalse(credentials.hashCode() == otherCredentials.hashCode());
    otherCredentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID, SA_CLIENT_EMAIL,
        SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, EMPTY_SCOPES, serverTransportFactory,
        tokenServer1);
    assertFalse(credentials.hashCode() == otherCredentials.hashCode());
    otherCredentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID, SA_CLIENT_EMAIL,
        SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, SCOPES, httpTransportFactory, tokenServer1);
    assertFalse(credentials.hashCode() == otherCredentials.hashCode());
    otherCredentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID, SA_CLIENT_EMAIL,
        SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, SCOPES, serverTransportFactory, tokenServer2);
    assertFalse(credentials.hashCode() == otherCredentials.hashCode());
  }

  @Test
  public void serialize() throws IOException, ClassNotFoundException {
    final URI tokenServer = URI.create("https://foo.com/bar");
    MockTokenServerTransportFactory transportFactory = new MockTokenServerTransportFactory();
    ServiceAccountCredentials credentials = ServiceAccountCredentials.fromPkcs8(SA_CLIENT_ID,
        SA_CLIENT_EMAIL, SA_PRIVATE_KEY_PKCS8, SA_PRIVATE_KEY_ID, SCOPES, transportFactory,
        tokenServer);
    ServiceAccountCredentials deserializedCredentials = serializeAndDeserialize(credentials);
    assertEquals(credentials, deserializedCredentials);
    assertEquals(credentials.hashCode(), deserializedCredentials.hashCode());
    assertEquals(credentials.toString(), deserializedCredentials.toString());
    assertSame(deserializedCredentials.clock, Clock.SYSTEM);
  }

  static GenericJson writeServiceAccountJson(
      String clientId, String clientEmail, String privateKeyPkcs8, String privateKeyId) {
    GenericJson json = new GenericJson();
    if (clientId != null) {
      json.put("client_id", clientId);
    }
    if (clientEmail != null) {
      json.put("client_email", clientEmail);
    }
    if (privateKeyPkcs8 != null) {
      json.put("private_key", privateKeyPkcs8);
    }
    if (privateKeyId != null) {
      json.put("private_key_id", privateKeyId);
    }
    json.put("type", GoogleCredentials.SERVICE_ACCOUNT_FILE_TYPE);
    return json;
  }

  static InputStream writeServiceAccountAccountStream(String clientId, String clientEmail,
      String privateKeyPkcs8, String privateKeyId) throws IOException {
    GenericJson json =
        writeServiceAccountJson(clientId, clientEmail, privateKeyPkcs8, privateKeyId);
    return TestUtils.jsonToInputStream(json);
  }
}
