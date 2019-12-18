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

public class IamMessage {

   private String contentType = null;
   private String iv = null;
   private String keyId = null;
   private String messageContext = null;
   private String messageId = null;
   private String messageType = null;
   private String signingCertUrl = null;
   private String sender = null;
   private String timestamp = null;
   private String version = null;
   private String body = null;

   public void setContentType(String v) {
      contentType = v;
   }
   public String getContentType() {
      return contentType;
   }

   public void setIv(String v) {
      iv = v;
   }
   public String getIv() {
      return iv;
   }

   public void setKeyId(String v) {
      keyId = v;
   }
   public String getKeyId() {
      return keyId;
   }

   public void setMessageContext(String v) {
      messageContext = v;
   }
   public String getMessageContext() {
      return messageContext;
   }

   public void setMessageId(String v) {
      messageId = v;
   }
   public String getMessageId() {
      return messageId;
   }

   public void setMessageType(String v) {
      messageType = v;
   }
   public String getMessageType() {
      return messageType;
   }

   public void setSigningCertUrl(String v) {
      signingCertUrl = v;
   }
   public String getSigningCertUrl() {
      return signingCertUrl;
   }

   public void setSender(String v) {
      sender = v;
   }
   public String getSender() {
      return sender;
   }

   public void setTimestamp(String v) {
      timestamp = v;
   }
   public String getTimestamp() {
      return timestamp;
   }

   public void setVersion(String v) {
      version = v;
   }
   public String getVersion() {
      return version;
   }

   public void setBody(String v) {
      body = v;
   }
   public String getBody() {
      return body;
   }
}

