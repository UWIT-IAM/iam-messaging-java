/* ========================================================================
 * Copyright (c) 2019 The University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

package edu.washington.iam.messaging;

import edu.washington.iam.messaging.IamMessage;
import edu.washington.iam.messaging.IamMessageException;
import edu.washington.iam.messaging.IamMessageHandler;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import java.security.cert.X509Certificate;

import org.bouncycastle.util.encoders.Base64;


import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

// import org.junit.runner.RunWith;


public class CryptTest {

   String encodedMessageFile = "src/test/data/msg.enc";
   String MessageBodyFile = "src/test/data/msg.body";
   private static Base64 b64;
   String config = "src/test/data/config";

   public void testParse() {

      IamMessageHandler handler = new IamMessageHandler();
      handler.init(config);

      // get the test document
      String sigdoc = null;
      try {
         sigdoc = new String(Files.readAllBytes(Paths.get(encodedMessageFile)));
      } catch (IOException e) {
         assertNotNull(null);
      }

      try {
         IamMessage msg = handler.parse(sigdoc);
         assertNotNull(msg);
         String orig = new String(Files.readAllBytes(Paths.get(MessageBodyFile)));
         assertEquals(orig, msg.getBody());
         X509Certificate cert = handler.getCertificate("https://groups.uw.edu/pubkeys/sign2.crt");
         assertNotNull(cert);
      } catch (IamMessageException e) {
         assertNotNull(null);
      } catch (IOException e) {
         assertNotNull(null);
      }

   }

}




