/*
 * Copyright 2022 ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package tech.pegasys.signers.fortanixdsm;

import java.util.Optional;

import com.fortanix.sdkms.v1.ApiClient;
import com.fortanix.sdkms.v1.ApiException;
import com.fortanix.sdkms.v1.Configuration;
import com.fortanix.sdkms.v1.api.AuthenticationApi;
import com.fortanix.sdkms.v1.api.SecurityObjectsApi;
import com.fortanix.sdkms.v1.auth.ApiKeyAuth;
import com.fortanix.sdkms.v1.model.AuthResponse;
import com.fortanix.sdkms.v1.model.KeyObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

// API library imports.
// import com.fortanix.sdkms.v1.api.EncryptionAndDecryptionApi;
// import com.fortanix.sdkms.v1.api.SecurityObjectsApi;
// import com.fortanix.sdkms.v1.model.DecryptRequest;
// import com.fortanix.sdkms.v1.model.DecryptResponse;
// import com.fortanix.sdkms.v1.model.EncryptRequest;
// import com.fortanix.sdkms.v1.model.EncryptResponse;
// import com.fortanix.sdkms.v1.model.ObjectType;

public class FortanixDSM {

  private static final Logger LOG = LogManager.getLogger();
  private String bearerToken;
  private final ApiClient client;

  private FortanixDSM(String server, String apiKey, Boolean debug, Boolean debug_tls) throws ApiException {
    client = new ApiClient();
    // Set the name of the server to talk to.
    client.setBasePath(server);

    // This optionally enables verbose logging in the API library.
    client.setDebugging(debug);

    // The default ApiClient (and its configured authorization) will be
    // used for constructing the specific API objects, such as
    // EncryptionAndDecryptionApi and SecurityObjectsApi.
    Configuration.setDefaultApiClient(client);

    // If you need a trust store for the server's certificate, you can
    // configure it here or via -Djavax.net.ssl.trustStore= on the
    // java command line.
    // if (truststore != null) {
    //   System.setProperty("javax.net.ssl.trustStore", truststore);
    // }

    // This optionally enables very verbose logging in the Java network
    // libraries.
    if (debug_tls) {
      System.setProperty("javax.net.debug", "all");
    }

    // When authenticating as an application, the API Key functions as
    // the entire HTTP basic auth token.
    client.setBasicAuthString(apiKey);

    // Acquire a bearer token to use for other APIs.
    AuthResponse response = new AuthenticationApi().authorize();
    bearerToken = response.getAccessToken();
    if (debug) {
      LOG.info("Received Bearer token %s\n", bearerToken);
    }

    // Configure the client library to use the bearer token.
    ApiKeyAuth bearerAuth = (ApiKeyAuth) client.getAuthentication("bearerToken");
    bearerAuth.setApiKey(bearerToken);
    bearerAuth.setApiKeyPrefix("Bearer");
  }

  public Optional<byte[]> fetchSecret(final String secretName) {
    try {
      KeyObject secret = new SecurityObjectsApi().getSecurityObjectValue(secretName);
      return Optional.of(secret.getValue());
    } catch (final ApiException e) {
      return Optional.empty();
    }
  }

  public void logout() {
    if (bearerToken != null) {
      // It is a good idea to terminate the session when you are done
      // using it. This minimizes the window of time in which an attacker
      // could steal your bearer token and use it.
      try {
        new AuthenticationApi().terminate();
      } catch (final ApiException e) {
        LOG.error("Error logging out: " + e.getMessage());
      }
      bearerToken = null;
    }
  }

  public static void main(String[] args) {
    String server = "https://apps.sdkms.fortanix.com";
    String apiKey =
        "OTA5NzMxZjAtYzliNy00NTg5LWI0MTEtYjhiZjlhZjExNmQ2OmN0NEM0bVExQjFTZUlfYlcyNVk4X3FnaURnd0JMN2lVUkROOFowUGVzX1BQN3BFSVVjX1lKZ3RJTGMwcWZtdUxLNTFSdlVMVUNKeGhCR1ZSdjN4ek13";
    boolean debug = false;
    boolean debug_tls = false;
    String keyId = "da589b59-986a-4b82-9b98-084d4727487e";
    FortanixDSM crypto;
    try {
      crypto = new FortanixDSM(server, apiKey, debug, debug_tls);
      Optional<byte[]> secret = crypto.fetchSecret(keyId);
      System.out.println(secret);
      crypto.logout();
    } catch (ApiException  e) {
      LOG.error(e);
    } catch (Exception e) {
      LOG.error(e);
    } 
  }
}
