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

import com.google.api.client.util.Clock;
import com.google.auth.Credentials;
import com.google.auth.RequestMetadataCallback;
import com.google.auth.http.AuthHttpConstants;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.MoreObjects;
import com.google.common.base.MoreObjects.ToStringHelper;
import com.google.common.base.Preconditions;
import com.google.common.collect.Iterables;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.ListenableFutureTask;
import com.google.common.util.concurrent.MoreExecutors;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceLoader;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.annotation.Nullable;

/**
 * Base type for Credentials using OAuth2.
 */
public class OAuth2Credentials extends Credentials {

  private static final long serialVersionUID = 4556936364828217687L;
  private static final long MINIMUM_TOKEN_MILLISECONDS = TimeUnit.MINUTES.toMillis(5);
  private static final long REFRESH_MARGIN_MILLISECONDS = MINIMUM_TOKEN_MILLISECONDS + TimeUnit.MINUTES.toMillis(1);

  // byte[] is serializable, so the lock variable can be final
  private volatile OAuthValue value = null;
  private transient ListenableFuture<OAuthValue> refreshTask;

  // Change listeners are not serialized
  private transient List<CredentialsChangedListener> changeListeners;
  // Until we expose this to the users it can remain transient and non-serializable
  @VisibleForTesting
  transient Clock clock = Clock.SYSTEM;

  /**
   * Returns the credentials instance from the given access token.
   *
   * @param accessToken the access token
   * @return the credentials instance
   */
  public static OAuth2Credentials of(AccessToken accessToken) {
    return OAuth2Credentials.newBuilder().setAccessToken(accessToken).build();
  }

  /**
   * Default constructor.
   **/
  protected OAuth2Credentials() {
    this(null);
  }

  /**
   * Constructor with explicit access token.
   *
   * @param accessToken Initial or temporary access token.
   **/
  @Deprecated
  public OAuth2Credentials(AccessToken accessToken) {
    if (accessToken != null) {
      this.value = OAuthValue.create(accessToken);
    }
  }

  @Override
  public String getAuthenticationType() {
    return "OAuth2";
  }

  @Override
  public boolean hasRequestMetadata() {
    return true;
  }

  @Override
  public boolean hasRequestMetadataOnly() {
    return true;
  }

  public final AccessToken getAccessToken() {
    OAuthValue localState = value;
    if (localState != null) {
      return localState.temporaryAccess;
    }
    return null;
  }

  @Override
  public void getRequestMetadata(final URI uri, Executor executor,
      final RequestMetadataCallback callback) {

    Futures.addCallback(asyncFetch(executor),
        new FutureCallbackToMetadataCallbackAdapter(callback), MoreExecutors.directExecutor());
  }

  /**
   * Provide the request metadata by ensuring there is a current access token and providing it
   * as an authorization bearer token.
   */
  @Override
  public Map<String, List<String>> getRequestMetadata(URI uri) throws IOException {
    return unwrapDirectFuture(asyncFetch(MoreExecutors.directExecutor())).requestMetadata;
  }

  /**
   * Refresh the token by discarding the cached token and metadata and requesting the new ones.
   */
  @Override
  public void refresh() throws IOException {
    unwrapDirectFuture(refreshAsync(MoreExecutors.directExecutor()));
  }

  // Async cache impl begin ------
  private synchronized ListenableFuture<OAuthValue> asyncFetch(Executor executor) {
    CacheState localState = getState();
    ListenableFuture<OAuthValue> localTask = refreshTask;

    // When token is no longer fresh, schedule a single flight refresh
    if (localState != CacheState.Fresh && localTask == null) {
      localTask = refreshAsync(executor);
    }

    // the refresh might've been executed using a DirectExecutor, so re-check current state
    localState = getState();

    // Immediately resolve the token token if its not expired, or wait for the refresh task to complete
    if (localState != CacheState.Expired) {
      return Futures.immediateFuture(value);
    } else {
      return localTask;
    }
  }


  private synchronized ListenableFuture<OAuthValue> refreshAsync(Executor executor) {
    final ListenableFutureTask<OAuthValue> task = ListenableFutureTask.create(new Callable<OAuthValue>() {
      @Override
      public OAuthValue call() throws Exception {
        return OAuthValue.create(refreshAccessToken());
      }
    });

    task.addListener(new Runnable() {
      @Override
      public void run() {
        finishRefreshAsync(task);
      }
    }, MoreExecutors.directExecutor());

    refreshTask = task;
    executor.execute(task);

    return task;
  }

  private synchronized void finishRefreshAsync(ListenableFuture<OAuthValue> finishedTask) {
    try {
      this.value = finishedTask.get();
      for (CredentialsChangedListener listener : changeListeners) {
        listener.onChanged(this);
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    } catch (Exception e) {
      // noop
    } finally {
      if (this.refreshTask == finishedTask) {
        this.refreshTask = null;
      }
    }
  }

  /**
   * Unwraps the value from the future.
   *
   * <p>Under most circumstances, the underlying future will already be resolved by the DirectExecutor.
   * In those cases, the error stacktraces will be rooted in the caller's call tree. However,
   * in some cases when async and sync usage is mixed, it's possible that a blocking call will await
   * an async future. In those cases, the stacktrace will be orphaned and be rooted in a thread of
   * whatever executor the async call used. This doesn't affect correctness and is extremely unlikely.
   */
  private static <T> T unwrapDirectFuture(Future<T> future) throws IOException {
    try {
      return future.get();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted while asynchronously refreshing the access token", e);
    } catch (ExecutionException e) {
      Throwable cause = e.getCause();
      if (cause instanceof IOException) {
        throw (IOException) cause;
      } else if (cause instanceof RuntimeException) {
        throw (RuntimeException)cause;
      } else {
        throw new IOException("Unexpected error refreshing access token", cause);
      }
    }
  }

  private CacheState getState() {
    OAuthValue localValue = value;

    if (localValue == null) {
      return CacheState.Expired;
    }

    Long expiresAtMillis = localValue.temporaryAccess.getExpirationTimeMillis();

    if (expiresAtMillis == null) {
      return CacheState.Fresh;
    }

    long remainingMillis = expiresAtMillis - clock.currentTimeMillis();

    if (remainingMillis < MINIMUM_TOKEN_MILLISECONDS) {
      return CacheState.Expired;
    }

    if (remainingMillis < REFRESH_MARGIN_MILLISECONDS) {
      return CacheState.Stale;
    }

    return CacheState.Fresh;
  }
  // -- async cache end

  /**
   * Method to refresh the access token according to the specific type of credentials.
   *
   * Throws IllegalStateException if not overridden since direct use of OAuth2Credentials is only
   * for temporary or non-refreshing access tokens.
   *
   * @throws IOException from derived implementations
   */
  public AccessToken refreshAccessToken() throws IOException {
    throw new IllegalStateException("OAuth2Credentials instance does not support refreshing the"
        + " access token. An instance with a new access token should be used, or a derived type"
        + " that supports refreshing.");
  }

  /**
   * Adds a listener that is notified when the Credentials data changes.
   *
   * <p>This is called when token content changes, such as when the access token is refreshed. This
   * is typically used by code caching the access token.
   *
   * @param listener The listener to be added.
   */
  public final synchronized void addChangeListener(CredentialsChangedListener listener) {
    if (changeListeners == null) {
      changeListeners = new ArrayList<>();
    }
    changeListeners.add(listener);
  }

  /**
   * Listener for changes to credentials.
   *
   * <p>This is called when token content changes, such as when the access token is refreshed. This
   * is typically used by code caching the access token.
   */
  public interface CredentialsChangedListener {

    /**
     * Notifies that the credentials have changed.
     *
     * <p>This is called when token content changes, such as when the access token is refreshed.
     * This is typically used by code caching the access token.
     *
     * @param credentials The updated credentials instance
     * @throws IOException My be thrown by listeners if saving credentials fails.
     */
    void onChanged(OAuth2Credentials credentials) throws IOException;
  }

  @Override
  public int hashCode() {
    return Objects.hash(value);
  }

  protected ToStringHelper toStringHelper() {
    OAuthValue localValue = value;

    Map<String, List<String>> requestMetadata = null;
    AccessToken temporaryAccess = null;

    if (localValue != null) {
      requestMetadata = localValue.requestMetadata;
      temporaryAccess = localValue.temporaryAccess;
    }
    return MoreObjects.toStringHelper(this)
        .add("requestMetadata", requestMetadata)
        .add("temporaryAccess", temporaryAccess);
  }

  @Override
  public String toString() {
    return toStringHelper().toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof OAuth2Credentials)) {
      return false;
    }
    OAuth2Credentials other = (OAuth2Credentials) obj;
    return Objects.equals(this.value, other.value);
  }

  private void readObject(ObjectInputStream input) throws IOException, ClassNotFoundException {
    input.defaultReadObject();
    clock = Clock.SYSTEM;
  }

  @SuppressWarnings("unchecked")
  protected static <T> T newInstance(String className) throws IOException, ClassNotFoundException {
    try {
      return (T) Class.forName(className).newInstance();
    } catch (InstantiationException | IllegalAccessException e) {
      throw new IOException(e);
    }
  }

  protected static <T> T getFromServiceLoader(Class<? extends T> clazz, T defaultInstance) {
    return Iterables.getFirst(ServiceLoader.load(clazz), defaultInstance);
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public Builder toBuilder() {
    return new Builder(this);
  }


  /**
   * Stores an immutable snapshot of the accesstoken owned by {@link OAuth2Credentials}
   */
  static class OAuthValue implements Serializable {
    private final AccessToken temporaryAccess;
    private final Map<String, List<String>> requestMetadata;

    static OAuthValue create(AccessToken token) {
      return new OAuthValue(
          token,
          Collections.singletonMap(
              AuthHttpConstants.AUTHORIZATION,
              Collections.singletonList(OAuth2Utils.BEARER_PREFIX + token.getTokenValue())));
    }

    private OAuthValue(AccessToken temporaryAccess,
        Map<String, List<String>> requestMetadata) {
      this.temporaryAccess = temporaryAccess;
      this.requestMetadata = requestMetadata;
    }

    @Override
    public boolean equals(Object obj) {
      if (!(obj instanceof OAuthValue)) {
        return false;
      }
      OAuthValue other = (OAuthValue) obj;
      return Objects.equals(this.requestMetadata, other.requestMetadata)
          && Objects.equals(this.temporaryAccess, other.temporaryAccess);
    }

    @Override
    public int hashCode() {
      return Objects.hash(temporaryAccess, requestMetadata);
    }
  }

  enum CacheState {
    Fresh,
    Stale,
    Expired;
  }

  static class FutureCallbackToMetadataCallbackAdapter implements FutureCallback<OAuthValue> {
    private final RequestMetadataCallback callback;

    public FutureCallbackToMetadataCallbackAdapter(RequestMetadataCallback callback) {
      this.callback = callback;
    }

    @Override
    public void onSuccess(@Nullable OAuthValue value) {
      callback.onSuccess(value.requestMetadata);
    }

    @Override
    public void onFailure(Throwable throwable) {
      callback.onFailure(throwable);
    }
  }

  public static class Builder {

    private AccessToken accessToken;

    protected Builder() {}

    protected Builder(OAuth2Credentials credentials) {
      this.accessToken = credentials.getAccessToken();
    }

    public Builder setAccessToken(AccessToken token) {
      this.accessToken = token;
      return this;
    }

    public AccessToken getAccessToken() {
      return accessToken;
    }

    public OAuth2Credentials build() {
      return new OAuth2Credentials(accessToken);
    }
  }
}
