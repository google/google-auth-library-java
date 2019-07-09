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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.util.Clock;
import com.google.auth.http.AuthHttpConstants;
import java.io.IOException;
import java.net.URI;
import java.security.PrivateKey;
import java.util.List;
import java.util.Map;
import org.junit.Test;

public class JwtCredentialsTest extends BaseSerializationTest {
  private static final String PRIVATE_KEY_ID =
      "d84a4fefcf50791d4a90f2d7af17469d6282df9d";
  private static final String PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n"
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
  private static final String JWT_ACCESS_PREFIX =
      ServiceAccountJwtAccessCredentials.JWT_ACCESS_PREFIX;
  private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();

  static PrivateKey getPrivateKey() {
    try {
      return ServiceAccountCredentials.privateKeyFromPkcs8(PRIVATE_KEY);
    } catch (IOException ex) {
      return null;
    }
  }

  @Test
  public void serialize() throws IOException, ClassNotFoundException {
    JwtCredentials.Claims claims = JwtCredentials.Claims.newBuilder()
        .setAudience("some-audience")
        .setIssuer("some-issuer")
        .setSubject("some-subject")
        .build();
    JwtCredentials credentials = JwtCredentials.newBuilder()
        .setClaims(claims)
        .setPrivateKey(getPrivateKey())
        .setPrivateKeyId(PRIVATE_KEY_ID)
        .build();

    JwtCredentials deserializedCredentials = serializeAndDeserialize(credentials);
    assertEquals(credentials, deserializedCredentials);
    assertEquals(credentials.hashCode(), deserializedCredentials.hashCode());
    assertEquals(credentials.toString(), deserializedCredentials.toString());
    assertSame(deserializedCredentials.getClock(), Clock.SYSTEM);
  }

  @Test
  public void builder_requiresPrivateKey() {
    try {
      JwtCredentials.Claims claims = JwtCredentials.Claims.newBuilder()
          .setAudience("some-audience")
          .setIssuer("some-issuer")
          .setSubject("some-subject")
          .build();
      JwtCredentials.newBuilder()
          .setClaims(claims)
          .setPrivateKeyId(PRIVATE_KEY_ID)
          .build();
      fail("Should throw exception");
    } catch (NullPointerException ex) {
      // expected
    }
  }

  @Test
  public void builder_requiresPrivateKeyId() {
    try {
      JwtCredentials.Claims claims = JwtCredentials.Claims.newBuilder()
          .setAudience("some-audience")
          .setIssuer("some-issuer")
          .setSubject("some-subject")
          .build();
      JwtCredentials.newBuilder()
          .setClaims(claims)
          .setPrivateKey(getPrivateKey())
          .build();
      fail("Should throw exception");
    } catch (NullPointerException ex) {
      // expected
    }
  }

  @Test
  public void builder_requiresClaims() {
    try {
      JwtCredentials.newBuilder()
          .setPrivateKeyId(PRIVATE_KEY_ID)
          .setPrivateKey(getPrivateKey())
          .build();
      fail("Should throw exception");
    } catch (NullPointerException ex) {
      // expected
    }
  }

  @Test
  public void builder_requiresCompleteClaims() {
    try {
      JwtCredentials.Claims claims = JwtCredentials.Claims.newBuilder()
          .build();
      JwtCredentials.newBuilder()
          .setClaims(claims)
          .setPrivateKeyId(PRIVATE_KEY_ID)
          .setPrivateKey(getPrivateKey())
          .build();
      fail("Should throw exception");
    } catch (IllegalStateException ex) {
      // expected
    }
  }
  @Test
  public void claims_merge_overwritesFields() {
    JwtCredentials.Claims claims1 = JwtCredentials.Claims.newBuilder()
        .setAudience("audience-1")
        .setIssuer("issuer-1")
        .setSubject("subject-1")
        .build();
    JwtCredentials.Claims claims2 = JwtCredentials.Claims.newBuilder()
        .setAudience("audience-2")
        .setIssuer("issuer-2")
        .setSubject("subject-2")
        .build();
    JwtCredentials.Claims merged = claims1.merge(claims2);

    assertEquals("audience-2", merged.getAudience());
    assertEquals("issuer-2", merged.getIssuer());
    assertEquals("subject-2", merged.getSubject());
  }

  @Test
  public void claims_merge_defaultValues() {
    JwtCredentials.Claims claims1 = JwtCredentials.Claims.newBuilder()
        .setAudience("audience-1")
        .setIssuer("issuer-1")
        .setSubject("subject-1")
        .build();
    JwtCredentials.Claims claims2 = JwtCredentials.Claims.newBuilder()
        .setAudience("audience-2")
        .build();
    JwtCredentials.Claims merged = claims1.merge(claims2);

    assertEquals("audience-2", merged.getAudience());
    assertEquals("issuer-1", merged.getIssuer());
    assertEquals("subject-1", merged.getSubject());
  }

  @Test
  public void claims_merge_null() {
    JwtCredentials.Claims claims1 = JwtCredentials.Claims.newBuilder().build();
    JwtCredentials.Claims claims2 = JwtCredentials.Claims.newBuilder().build();
    JwtCredentials.Claims merged = claims1.merge(claims2);

    assertNull(merged.getAudience());
    assertNull(merged.getIssuer());
    assertNull(merged.getSubject());
  }

  @Test
  public void claims_equals() {
    JwtCredentials.Claims claims1 = JwtCredentials.Claims.newBuilder()
        .setAudience("audience-1")
        .setIssuer("issuer-1")
        .setSubject("subject-1")
        .build();
    JwtCredentials.Claims claims2 = JwtCredentials.Claims.newBuilder()
        .setAudience("audience-1")
        .setIssuer("issuer-1")
        .setSubject("subject-1")
        .build();

    assertEquals(claims1, claims2);
  }

  @Test
  public void withClaims_overwritesClaims() throws IOException {
    JwtCredentials.Claims claims = JwtCredentials.Claims.newBuilder()
        .setAudience("some-audience")
        .setIssuer("some-issuer")
        .setSubject("some-subject")
        .build();
    JwtCredentials credentials = JwtCredentials.newBuilder()
        .setClaims(claims)
        .setPrivateKey(getPrivateKey())
        .setPrivateKeyId(PRIVATE_KEY_ID)
        .build();
    JwtCredentials.Claims claims2 = JwtCredentials.Claims.newBuilder()
        .setAudience("some-audience2")
        .setIssuer("some-issuer2")
        .setSubject("some-subject2")
        .build();
    JwtCredentials credentials2 = credentials.withClaims(claims2);
    Map<String, List<String>> metadata = credentials2.getRequestMetadata();
    verifyJwtAccess(metadata, "some-audience2","some-issuer2", "some-subject2", PRIVATE_KEY_ID);
  }

  @Test
  public void withClaims_defaultsClaims() throws IOException {
    JwtCredentials.Claims claims = JwtCredentials.Claims.newBuilder()
        .setAudience("some-audience")
        .setIssuer("some-issuer")
        .setSubject("some-subject")
        .build();
    JwtCredentials credentials = JwtCredentials.newBuilder()
        .setClaims(claims)
        .setPrivateKey(getPrivateKey())
        .setPrivateKeyId(PRIVATE_KEY_ID)
        .build();
    JwtCredentials.Claims claims2 = JwtCredentials.Claims.newBuilder().build();
    JwtCredentials credentials2 = credentials.withClaims(claims2);
    Map<String, List<String>> metadata = credentials2.getRequestMetadata();
    verifyJwtAccess(metadata, "some-audience","some-issuer", "some-subject", PRIVATE_KEY_ID);
  }

  @Test
  public void getRequestMetadata_hasJwtAccess() throws IOException {
    JwtCredentials.Claims claims = JwtCredentials.Claims.newBuilder()
        .setAudience("some-audience")
        .setIssuer("some-issuer")
        .setSubject("some-subject")
        .build();
    JwtCredentials credentials = JwtCredentials.newBuilder()
        .setClaims(claims)
        .setPrivateKey(getPrivateKey())
        .setPrivateKeyId(PRIVATE_KEY_ID)
        .build();

    Map<String, List<String>> metadata = credentials.getRequestMetadata();
    verifyJwtAccess(metadata, "some-audience","some-issuer", "some-subject", PRIVATE_KEY_ID);
  }

  private void verifyJwtAccess(Map<String, List<String>> metadata, String expectedAudience,
      String expectedIssuer, String expectedSubject, String expectedKeyId) throws IOException {
    assertNotNull(metadata);
    List<String> authorizations = metadata.get(AuthHttpConstants.AUTHORIZATION);
    assertNotNull("Authorization headers not found", authorizations);
    String assertion = null;
    for (String authorization : authorizations) {
      if (authorization.startsWith(JWT_ACCESS_PREFIX)) {
        assertNull("Multiple bearer assertions found", assertion);
        assertion = authorization.substring(JWT_ACCESS_PREFIX.length());
      }
    }
    assertNotNull("Bearer assertion not found", assertion);
    JsonWebSignature signature = JsonWebSignature.parse(JSON_FACTORY, assertion);
    assertEquals(expectedIssuer, signature.getPayload().getIssuer());
    assertEquals(expectedSubject, signature.getPayload().getSubject());
    assertEquals(expectedAudience, signature.getPayload().getAudience());
    assertEquals(expectedKeyId, signature.getHeader().getKeyId());
  }
}
