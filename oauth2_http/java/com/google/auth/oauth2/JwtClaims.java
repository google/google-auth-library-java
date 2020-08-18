/*
 * Copyright 2019, Google LLC
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
 *    * Neither the name of Google LLC nor the names of its
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

import com.google.api.client.util.Preconditions;
import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import java.io.Serializable;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * Value class representing the set of fields used as the payload of a JWT token.
 *
 * <p>To create and customize claims, use the builder:
 *
 * <pre><code>
 * Claims claims = Claims.newBuilder()
 *     .setAudience("https://example.com/some-audience")
 *     .setIssuer("some-issuer@example.com")
 *     .setSubject("some-subject@example.com")
 *     .build();
 * </code></pre>
 */
@AutoValue
public abstract class JwtClaims implements Serializable {
  private static final long serialVersionUID = 4974444151019426702L;

  @Nullable
  abstract String getAudience();

  @Nullable
  abstract String getIssuer();

  @Nullable
  abstract String getSubject();

  /**
   * Returns additional claims for this object. The returned map is not guaranteed to be mutable.
   *
   * @return additional claims
   */
  abstract Map<String, ?> getAdditionalClaims();

  public static Builder newBuilder() {
    return new AutoValue_JwtClaims.Builder().setAdditionalClaims(ImmutableMap.<String, Object>of());
  }

  /**
   * Returns a new Claims instance with overridden fields.
   *
   * <p>Any non-null field will overwrite the value from the original claims instance.
   *
   * @param other claims to override
   * @return new claims
   */
  public JwtClaims merge(JwtClaims other) {
    ImmutableMap.Builder<String, Object> newClaimsBuilder = ImmutableMap.builder();
    newClaimsBuilder.putAll(getAdditionalClaims());
    newClaimsBuilder.putAll(other.getAdditionalClaims());

    return newBuilder()
        .setAudience(other.getAudience() == null ? getAudience() : other.getAudience())
        .setIssuer(other.getIssuer() == null ? getIssuer() : other.getIssuer())
        .setSubject(other.getSubject() == null ? getSubject() : other.getSubject())
        .setAdditionalClaims(newClaimsBuilder.build())
        .build();
  }

  /**
   * Returns whether or not this set of claims is complete.
   *
   * <p>Audience, issuer, and subject are required to be set in order to use the claim set for a JWT
   * token. An incomplete Claims instance is useful for overriding claims when using {@link
   * ServiceAccountJwtAccessCredentials#jwtWithClaims(JwtClaims)} or {@link
   * JwtCredentials#jwtWithClaims(JwtClaims)}.
   *
   * @return true if all required fields have been set; false otherwise
   */
  public boolean isComplete() {
    return getAudience() != null && getIssuer() != null && getSubject() != null;
  }

  @AutoValue.Builder
  public abstract static class Builder {
    /** Basic types supported by JSON standard. */
    private static List<Class<? extends Serializable>> SUPPORTED_BASIC_TYPES =
        ImmutableList.of(
            String.class,
            Integer.class,
            Double.class,
            Float.class,
            Boolean.class,
            Date.class,
            String[].class,
            Integer[].class,
            Double[].class,
            Float[].class,
            Boolean[].class,
            Date[].class);

    private static final String ERROR_MESSAGE =
        "Invalid type on additional claims. Valid types are String, Integer, "
            + "Double, Float, Boolean, Date, List and Map. Map keys must be Strings.";

    public abstract Builder setAudience(String audience);

    public abstract Builder setIssuer(String issuer);

    public abstract Builder setSubject(String subject);

    public abstract Builder setAdditionalClaims(Map<String, ?> additionalClaims);

    protected abstract JwtClaims autoBuild();

    public JwtClaims build() {
      JwtClaims claims = autoBuild();
      Preconditions.checkState(validateClaims(claims.getAdditionalClaims()), ERROR_MESSAGE);
      return claims;
    }

    /**
     * Validate if the objects on a Map are valid for a JWT claim.
     *
     * @param claims Map of claim objects to be validated
     */
    private static boolean validateClaims(Map<String, ?> claims) {
      if (!validateKeys(claims)) {
        return false;
      }

      for (Object claim : claims.values()) {
        if (!validateObject(claim)) {
          return false;
        }
      }

      return true;
    }

    /**
     * Validates if the object is a valid JSON supported type.
     *
     * @param object to be evaluated
     */
    private static final boolean validateObject(@Nullable Object object) {
      // According to JSON spec, null is a valid value.
      if (object == null) {
        return true;
      }

      if (object instanceof List) {
        return validateCollection((List) object);
      } else if (object instanceof Map) {
        return validateKeys((Map) object) && validateCollection(((Map) object).values());
      }

      return isSupportedValue(object);
    }

    /**
     * Validates the keys on a given map. Keys must be Strings.
     *
     * @param map map to be evaluated
     */
    private static final boolean validateKeys(Map map) {
      for (Object key : map.keySet()) {
        if (!(key instanceof String)) {
          return false;
        }
      }

      return true;
    }

    /**
     * Validates if a collection is a valid JSON value. Empty collections are considered valid.
     *
     * @param collection collection to be evaluated
     */
    private static final boolean validateCollection(Collection collection) {
      if (collection.isEmpty()) {
        return true;
      }

      for (Object item : collection) {
        if (!validateObject(item)) {
          return false;
        }
      }

      return true;
    }

    /**
     * Validates if the given object is an instance of a valid JSON basic type.
     *
     * @param value object to be evaluated.
     */
    private static final boolean isSupportedValue(Object value) {
      Class clazz = value.getClass();
      return SUPPORTED_BASIC_TYPES.contains(clazz);
    }
  }
}
