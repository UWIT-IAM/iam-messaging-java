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

import edu.washington.iam.messaging.IamMessage;
import edu.washington.iam.messaging.IamMessageException;
import edu.washington.iam.messaging.IamMessageHandler;

import java.nio.file.Files;
import java.nio.file.Paths;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import org.bouncycastle.util.encoders.Base64;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonElement;
import com.google.gson.JsonArray;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonParseException;


public class Test {

   String encodedMessageFile = "./data/msg.enc";
   String MessageBodyFile = "./data/msg.body";
   private static Base64 b64;
   String config = "./config";

   public static void main(String[] args) {
      Test test = new Test();
      b64 = new Base64();
      test.run();
   }

   private void logit(String msg) {
      System.out.println(msg);
   }

   public void run() {
     IamMessageHandler handler = new IamMessageHandler();
     handler.init(config);

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
         IamMessage msg = handler.parse(sigdoc);
         // verify body
         String orig = new String(Files.readAllBytes(Paths.get(MessageBodyFile)));
         if (orig.equals(msg.getBody())) System.out.println("Message body matches.");
      } catch (IamMessageException e) {
         logit(e.toString());
         System.exit(1);
      } catch (IOException e) {
         logit(e.toString());
         System.exit(1);
      }
      


   }
}

