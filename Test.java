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

// package edu.washington.iam.tools;

import edu.washington.iam.messaging.IamMessageException;
import edu.washington.iam.messaging.IamMessageHandler;
import edu.washington.iam.messaging.AWS;

import java.nio.file.Files;
import java.nio.file.Paths;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.io.FileNotFoundException;
import java.util.HashMap;
import java.util.Map;

import java.security.cert.X509Certificate;

import org.bouncycastle.util.encoders.Base64;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonElement;
import com.google.gson.JsonArray;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonParseException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class Test {

   final Logger logger = LoggerFactory.getLogger(Test.class);


   String encodedMessageFile = "src/test/data/msg.enc";
   String MessageBodyFile = "src/test/data/msg.body";
   private static Base64 b64;
   String config = "src/test/data/config";

   public static void main(String[] args) throws Exception {
      Test test = new Test();
      b64 = new Base64();
      test.run();
   }

   private void logit(String msg) {
      System.out.println(msg);
   }

   private boolean is_simple(String in) {
      // return in!=null && in.chars().allMatch(Character::isLetterOrDigit);
      return in!=null && in.chars().allMatch(c -> Character.isLetterOrDigit(c)||c=='-');
   }

   public void run() throws Exception {
     logger.info("Starting");

/**   AWS sns send test **/
      AWS aws = new AWS();
      aws.init("/home/fox/certs/msg-settings-west.json");
      String res = aws.sendMessage("Hello, world", "arn:aws:sns:us-west-2:611509864246:json-test-1", null);
      System.out.println(res);
      
/**  Encoder/Decoder test 
     IamMessageHandler handler = new IamMessageHandler();
     handler.init(config);

     // encode
      Map<String,String> info = new HashMap();
      info.put("contentType", "json");
      info.put("messageType", "ok-message-type");
      info.put("messageContext", "Some valid content \" '%'");
      info.put("sender", "valid-sender");
      String enc = handler.encodeMessage("Some message", info, "testcrypt2", "testsig1");
      System.out.println(enc);
      System.out.println("decoding...");
      Map<String,String> decmsg = handler.decodeMessage(enc);

      System.out.println(decmsg);
         System.exit(1);
**/

/**   Compability test.  Doc from python version
      // get the doc ( test file with encoded message )
      String sigdoc = null;
      System.out.println("Processing encoded message from " + encodedMessageFile);
      System.out.println("Original message body text from " + MessageBodyFile);
      try {
         sigdoc = new String(Files.readAllBytes(Paths.get(encodedMessageFile)));
         logit("doc=" + sigdoc);
      } catch (IOException e) {
         logit(e.toString());
         System.exit(1);
      }

      try {
         Map<String,String> msg = handler.decodeMessage(sigdoc);
         // IamMessage msg = handler.decodeMessage(sigdoc);
         // verify body
         String orig = new String(Files.readAllBytes(Paths.get(MessageBodyFile)));
         // if (orig.equals(msg.getBody())) System.out.println("Message body matches.");
         if (orig.equals(msg.get("body"))) System.out.println("Message body matches.");
         X509Certificate cert = handler.getCertificate("https://groups.uw.edu/pubkeys/sign2.crt");
         logit(cert.getSubjectX500Principal().getName());
      } catch (IamMessageException e) {
         logit(e.toString());
         System.exit(1);
      } catch (IOException e) {
         logit(e.toString());
         System.exit(1);
      }
 **/  



   }
}

