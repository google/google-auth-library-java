/*
 * Copyright 2019, Google Inc. All rights reserved.
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

import com.google.api.client.http.*;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.GenericData;
import com.google.auth.ServiceAccountSigner;
import com.google.common.io.BaseEncoding;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

class IamUtils {
  private static final String SIGN_BLOB_URL_FORMAT = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:signBlob";
  private static final String PARSE_ERROR_MESSAGE = "Error parsing error message response. ";
  private static final String PARSE_ERROR_SIGNATURE = "Error parsing signature response. ";

  public static byte[] sign(String serviceAccountEmail, Map<String, List<String>> requestHeaders, HttpRequestFactory requestFactory, byte[] toSign) {
    BaseEncoding base64 = BaseEncoding.base64();
    String signature;
    try {
      signature = getSignature(serviceAccountEmail, requestHeaders, requestFactory, base64.encode(toSign));
    } catch (IOException ex) {
      throw new ServiceAccountSigner.SigningException("Failed to sign the provided bytes", ex);
    }
    return base64.decode(signature);
  }

  private static String getSignature(String serviceAccountEmail, Map<String, List<String>> requestHeaders, HttpRequestFactory requestFactory, String bytes) throws IOException {
    String signBlobUrl = String.format(SIGN_BLOB_URL_FORMAT, serviceAccountEmail);
    GenericUrl genericUrl = new GenericUrl(signBlobUrl);

    GenericData signRequest = new GenericData();
    signRequest.set("payload", bytes);
    JsonHttpContent signContent = new JsonHttpContent(OAuth2Utils.JSON_FACTORY, signRequest);
    HttpRequest request = requestFactory.buildPostRequest(genericUrl, signContent);

    HttpHeaders headers = request.getHeaders();
    for (Map.Entry<String, List<String>> entry : requestHeaders.entrySet()) {
      headers.put(entry.getKey(), entry.getValue());
    }
    JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY);
    request.setParser(parser);
    request.setThrowExceptionOnExecuteError(false);

    HttpResponse response = request.execute();
    int statusCode = response.getStatusCode();
    if (statusCode >= 400 && statusCode < HttpStatusCodes.STATUS_CODE_SERVER_ERROR) {
      GenericData responseError = response.parseAs(GenericData.class);
      Map<String, Object> error = OAuth2Utils.validateMap(responseError, "error", PARSE_ERROR_MESSAGE);
      String errorMessage = OAuth2Utils.validateString(error, "message", PARSE_ERROR_MESSAGE);
      throw new IOException(String.format("Error code %s trying to sign provided bytes: %s",
              statusCode, errorMessage));
    }
    if (statusCode != HttpStatusCodes.STATUS_CODE_OK) {
      throw new IOException(String.format("Unexpected Error code %s trying to sign provided bytes: %s", statusCode,
              response.parseAsString()));
    }
    InputStream content = response.getContent();
    if (content == null) {
      // Throw explicitly here on empty content to avoid NullPointerException from parseAs call.
      // Mock transports will have success code with empty content by default.
      throw new IOException("Empty content from sign blob server request.");
    }

    GenericData responseData = response.parseAs(GenericData.class);
    return OAuth2Utils.validateString(responseData, "signedBlob", PARSE_ERROR_SIGNATURE);
  }
}