/*
 * Copyright 2020 ConsenSys AG.
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static tech.pegasys.signers.fortanixdsm.FortanixDSM.createWithApiKeyCredential;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.fortanix.sdkms.v1.ApiException;

public class FortanixDSMTest {
  private static final String SERVER = System.getenv("DSM_SERVER");
  private static final String API_KEY = System.getenv("API_KEY");
  private static final String KEY_ID = System.getenv("KEY_ID");

  @BeforeAll
  public static void setup() {
    Assumptions.assumeTrue(SERVER != null, "Set DSM_SERVER environment variable");
    Assumptions.assumeTrue(API_KEY != null, "Set API_KEY environment variable");
    Assumptions.assumeTrue(KEY_ID != null, "Set KEY_ID environment variable");
  }

  @Test
  void connectingWithInvalidCredentialThrowsException() {
    assertThat(SERVER).isEqualTo("world");
    assertThatExceptionOfType(ApiException.class)
        .isThrownBy(() -> createWithApiKeyCredential(SERVER, API_KEY, true, true));
  }
}
