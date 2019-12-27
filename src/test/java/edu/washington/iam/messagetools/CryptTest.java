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

import edu.washington.iam.messaging.IamMessageException;
import edu.washington.iam.messaging.IamMessageHandler;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

import java.security.cert.X509Certificate;

import org.bouncycastle.util.encoders.Base64;


import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

// import org.junit.runner.RunWith;


public class CryptTest {

   String encodedMessageFile = "src/test/data/msg.enc";
   String MessageBodyFile = "src/test/data/msg.body";
   private static Base64 b64;
   String config = "src/test/data/config";

   /* Test decode of python generated message */
   @Test
   public void testParseFromPython() throws Exception {

      IamMessageHandler handler = new IamMessageHandler();
      handler.init(config);

      // get the test document
      String sigdoc = new String(Files.readAllBytes(Paths.get(encodedMessageFile)));
      Map<String,String> msg = handler.decodeMessage(sigdoc);
      assertNotNull(msg);
      String orig = new String(Files.readAllBytes(Paths.get(MessageBodyFile)));
      assertEquals(orig, msg.get("body"));
      X509Certificate cert = handler.getCertificate("https://groups.uw.edu/pubkeys/sign2.crt");
      assertNotNull(cert);
   }

   private String validContent = "Some valid content \" '%'";
   private Map<String, String> good_info() {
      Map<String, String> info = new HashMap();
      info.put("contentType", "json");
      info.put("messageType", "ok-message-type");
      info.put("messageContext", validContent);
      info.put("sender", "valid-sender");
      return info;
   }
      
   /* Test encode/decode w/o encrypt */
   @Test
   public void testSign1() throws Exception {

      IamMessageHandler handler = new IamMessageHandler();
      handler.init(config);
      String orig = new String(Files.readAllBytes(Paths.get(MessageBodyFile)));
      Map<String, String> info = good_info();
      String encoded_message = handler.encodeMessage(orig, info, null, "testsig1");
      Map<String,String> msg = handler.decodeMessage(encoded_message);
      assertNotNull(msg);
      assertEquals(orig, msg.get("body"));
      assertEquals(validContent, msg.get("messageContext"));
   }

   /* Test encode/decode with encrypt */
   @Test
   public void testSign2() throws Exception {

      IamMessageHandler handler = new IamMessageHandler();
      handler.init(config);
      String orig = new String(Files.readAllBytes(Paths.get(MessageBodyFile)));
      Map<String, String> info = good_info();
      String encoded_message = handler.encodeMessage(orig, info, "testcrypt2", "testsig1");
      Map<String,String> msg = handler.decodeMessage(encoded_message);
      assertNotNull(msg);
      assertEquals(orig, msg.get("body"));
      assertEquals(validContent, msg.get("messageContext"));
   }

   @Test
   public void testBadMessage_1() {
      IamMessageHandler handler = new IamMessageHandler();
      assertThrows(FileNotFoundException.class, () -> {
        handler.init("src/test/data/config.not");
      });
   }

   @Test
   public void testBadMessage_2() throws Exception {
      IamMessageHandler handler = new IamMessageHandler();
      handler.init(config);
      Map<String,String> info = good_info();
      info.put("messageType", "bad message type");
      assertThrows(IamMessageException.class, () -> {
        handler.encodeMessage("Some message", info, null, "testsig1");
      });
   }

   @Test
   public void testBadMessage_3() throws Exception {
      IamMessageHandler handler = new IamMessageHandler();
      handler.init(config);
      Map<String,String> info = good_info();
      info.remove("sender");
      assertThrows(IamMessageException.class, () -> {
        handler.encodeMessage("Some message", info, null, "testsig1");
      });
   }

   @Test
   public void testBadMessage_4() throws Exception {
      IamMessageHandler handler = new IamMessageHandler();
      handler.init(config);
      Map<String,String> info = good_info();
      assertThrows(IamMessageException.class, () -> {
        handler.encodeMessage("Some message", info, null, "testsig9");
      });
   }

}




