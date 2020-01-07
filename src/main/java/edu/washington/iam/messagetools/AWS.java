/* ========================================================================
 * Copyright (c) 2020 The University of Washington
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

import java.nio.file.Files;
import java.nio.file.Paths;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

// version 2.x api
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.MessageAttributeValue;
import software.amazon.awssdk.services.sns.model.PublishRequest;
import software.amazon.awssdk.services.sns.model.PublishResponse;


import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonElement;
import com.google.gson.JsonArray;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonParseException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AWS {

   final Logger logger = LoggerFactory.getLogger(AWS.class);

   /* SNS snsClient */
   SnsClient snsClient = null;

   /* Send a message.  
      b64message: encoded (signed and encrypted) message
      arn: ARN to publist to
      attributes: attributes
    */

   public String sendMessage(String message, String arn, Map<String, String> attributes) {
      // PublishRequest publishReq = new PublishRequest().withTopicArn(arn);
      PublishRequest.Builder publishReqB = PublishRequest.builder().topicArn(arn);
      publishReqB.message(message);

      // add attributes
      if (attributes!=null) {
         Map<String, MessageAttributeValue> msgAttrs = new HashMap();
         for (Map.Entry<String,String> attr: attributes.entrySet()) {
            MessageAttributeValue mav = MessageAttributeValue.builder().stringValue(attr.getValue()).build();
            msgAttrs.put(attr.getKey(), mav);
         }
         publishReqB.messageAttributes(msgAttrs);
      }
      PublishResponse res = snsClient.publish(publishReqB.build());
      return res.messageId();
   }



   private String getJson(JsonObject obj, String key) {
      JsonPrimitive p = obj.getAsJsonPrimitive(key);
      if (p==null) return null;
      return p.getAsString();
   }

   /* Initialize: Build client; Set region.
    */

   public void init(String configFile) throws IamMessageException, FileNotFoundException, IOException {
      logger.debug("AWS config: " + configFile);
      FileInputStream file = new FileInputStream(configFile);
      byte[] keyBytes = new byte[file.available()];
      file.read(keyBytes);
      file.close();
      String configString = new String(keyBytes, "UTF-8");

      JsonParser parser = new JsonParser();
      JsonObject obj = parser.parse(configString).getAsJsonObject();
      JsonObject aws_obj = (JsonObject) obj.getAsJsonObject("aws_conf");
      String key = getJson(aws_obj,"default_key");
      String keyId = getJson(aws_obj,"default_keyid");

      AwsCredentials creds = AwsBasicCredentials.create(keyId, key);
      AwsCredentialsProvider cprov = StaticCredentialsProvider.create(creds);
      snsClient = SnsClient.builder().region(Region.of(getJson(aws_obj,"region"))).credentialsProvider(cprov).build();
      
   }
}
