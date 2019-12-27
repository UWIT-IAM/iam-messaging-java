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

import java.nio.file.Files;
import java.nio.file.Paths;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Security;
import java.security.Signature;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.SignatureException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PSSParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;

import java.time.ZonedDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
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

public class IamMessageHandler {

   final Logger logger = LoggerFactory.getLogger(IamMessageHandler.class);

   private static Base64 b64;

   static {
      Security.addProvider(new BouncyCastleProvider());
   }

   /* List of signing certs by url (for verify) */
   Map<String, X509Certificate> signingCerts = new Hashtable();
   
   /* List of signing keys (for sign) */
   private class SigningKey {
      public String url;  // public key url
      public RSAPrivateKey key;
   }
   Map<String, SigningKey> signingKeys = new Hashtable();

   /* Add a private key for signing operation */
   public void addSigningKey(String id, String url, String keyfile) throws IamMessageException {
      SigningKey key = new SigningKey();
      key.url = url;
      key.key = getPrivateKey(keyfile);
      signingKeys.put(id, key);
   }
   
   /* List of cryption keys */
   Map<String, byte[]> cryptKeys = new Hashtable();
   
   /* Add a crypt key */
   public void addCryptKey(String id, String key64) {
      cryptKeys.put(id, b64.decode(key64));
   }

   /* CA filename */
   private String ca_file = null;

   /* Verify a string is 'simple' */
   private String if_simple(String in) throws IamMessageException {
      if (in!=null && in.chars().allMatch(c -> Character.isLetterOrDigit(c)||c=='-')) return in;
      throw new IamMessageException("Invalid string in header: " + in);
   }

   /* Encode a message ( sign and possibly encrypt ) 
      Reutrns base64 enncoded string
      */

   public String encodeMessage(String msg, Map<String,String> msg_info, String cryptId, String signId) throws IamMessageException, InvalidKeyException {
      
      Map<String,Object> message = new HashMap();
      Map<String,String> header = new HashMap();
      String body64 = null;
      String body = null;
      SigningKey signKey = signingKeys.get(signId);
      if (signKey==null) throw new IamMessageException("Signing keyid not found: " + signId);
   
      header.put("version", "UWIT-2");

      header.put("contentType", if_simple(msg_info.get("contentType")));
      if (!msg_info.containsKey("messageContext")) throw new IamMessageException("Invalid header: missing messageContext");
      header.put("messageContext", new String(b64.encode(msg_info.get("messageContext").getBytes())));
      header.put("messageType", if_simple(msg_info.get("messageType")));
      header.put("sender", if_simple(msg_info.get( "sender")));

      header.put("messageId", UUID.randomUUID().toString());
      header.put("timestamp", ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT));
      header.put("signingCertUrl", signKey.url);
      logger.debug("Processing message " + header.get("messageId") + " - " + header.get("messageType"));

      /* possibly encrypt body text */
      if (cryptId!=null) {
         try {
            // cryptkey
            header.put("keyId", cryptId);
            byte[] cryptKey = cryptKeys.get(cryptId);
            if (cryptKey==null) throw new IamMessageException("Encryption key not found: " + cryptId);
            // iv
            SecureRandom srandom = new SecureRandom();
            byte[] iv = new byte[128/8];
            srandom.nextBytes(iv);
            header.put("iv", new String(b64.encode(iv)));
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            SecretKeySpec skeySpec = new SecretKeySpec(cryptKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
            body64 = new String(b64.encode(cipher.doFinal(msg.getBytes("UTF-8"))));
         } catch (NoSuchAlgorithmException e) {
            throw new IamMessageException(e.getMessage());
         } catch (InvalidAlgorithmParameterException e) {
            throw new IamMessageException(e.getMessage());
         } catch (InvalidKeyException e) {
            throw new IamMessageException(e.getMessage());
         } catch (UnsupportedEncodingException e) {
            throw new IamMessageException(e.getMessage());
         } catch (NoSuchPaddingException e) {
            throw new IamMessageException(e.getMessage());
         } catch (IllegalBlockSizeException e) {
            throw new IamMessageException(e.getMessage());
         } catch (BadPaddingException e) {
            throw new IamMessageException(e.getMessage());
         }
      } else {
         // just base64 encode
         try {
            body64 = new String(b64.encode(msg.getBytes("UTF-8")));
         } catch (UnsupportedEncodingException e) {
            throw new IamMessageException(e.getMessage());
         }
      }

      /* sign */
      try {
         Signature signature = Signature.getInstance("SHA256withRSA/PSS");
         signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
         signature.initSign(signKey.key);
         String sigmsg = buildSigMessage(header, body64);
         byte[] bsigmsg = sigmsg.getBytes("UTF-8");
         signature.update(bsigmsg);
         byte[] sigbytes = signature.sign();
         header.put("signature", new String(b64.encode(sigbytes)));
      } catch (NoSuchAlgorithmException e) {
         throw new IamMessageException(e.getMessage());
      } catch (InvalidAlgorithmParameterException e) {
         throw new IamMessageException(e.getMessage());
      // } catch (InvalidKeyException e) {
      //    throw new IamMessageException(e.getMessage());
      } catch (UnsupportedEncodingException e) {
         throw new IamMessageException(e.getMessage());
      } catch (SignatureException e) {
         throw new IamMessageException(e.getMessage());
      }
      message.put("header", header);
      message.put("body", body64);
      String ret1 = new Gson().toJson(message);
      String ret = new String(b64.encode(ret1.getBytes()));
      return ret;
   }

   /* parse an encoded message ( base64, with signature verify and possible decryption ) */

   public Map<String,String> decodeMessage(String encodedMessage) throws IamMessageException {

      Map<String,String> message = new HashMap();
      String certUrl = null;
      JsonObject j_header = null;
      String body64 = null;
      String body = null;
      JsonParser parser = new JsonParser();
      JsonObject obj = parser.parse(new String(b64.decode(encodedMessage))).getAsJsonObject();
      j_header = obj.getAsJsonObject("header");
      certUrl = getJson(j_header, "signingCertUrl");
      logger.debug(certUrl);

      // verify this is message we can handle
      String vers = getJson(j_header, "version");
      if (!vers.equals("UWIT-2")) throw new IamMessageException("unknown version: " + vers);
      message.put("version", vers);
      message.put("contentType", getJson(j_header, "contentType"));
      message.put("messageContext", getJson(j_header, "messageContext"));
      message.put("messageId", getJson(j_header, "messageId"));
      message.put("messageType", getJson(j_header, "messageType"));
      message.put("sender", getJson(j_header, "sender"));
      message.put("timestamp", getJson(j_header, "timestamp"));
      message.put("signingCertUrl", certUrl);
      message.put("iv", getJson(j_header, "iv"));
      message.put("keyId", getJson(j_header, "keyId"));
      logger.debug("Processing message " + message.get("messageId") + " - " + message.get("messageType"));

      body64 = getJson(obj, "body");
      logger.debug(body64);

      // verify signature
      try {
         X509Certificate sigcert = getCertificate(certUrl);
         String sigmsg = buildSigMessage(message, body64);
         byte[] signature_in = b64.decode(getJson(j_header, "signature"));
         PublicKey sigkey = sigcert.getPublicKey();
      
         Signature signature = Signature.getInstance("SHA256withRSA/PSS");
         signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
         signature.initVerify(sigkey);
         byte[] bsigmsg = sigmsg.getBytes("UTF-8");
         signature.update(bsigmsg);
         boolean isCorrect = signature.verify(signature_in);
         if (!isCorrect) throw new IamMessageException("Signature verify fails");
      } catch (NoSuchAlgorithmException e) {
         throw new IamMessageException(e.getMessage());
      } catch (InvalidAlgorithmParameterException e) {
         throw new IamMessageException(e.getMessage());
      } catch (InvalidKeyException e) {
         throw new IamMessageException(e.getMessage());
      } catch (UnsupportedEncodingException e) {
         throw new IamMessageException(e.getMessage());
      } catch (SignatureException e) {
         throw new IamMessageException(e.getMessage());
      }

      // decrypt the message body as needed
      if (message.get("keyId")!=null) {
         try {
            byte[] iv64 = message.get("iv").getBytes("UTF-8");
            byte[] ivb = b64.decode(iv64);
            IvParameterSpec iv = new IvParameterSpec(ivb);
            byte[] key = (byte[]) cryptKeys.get(message.get("keyId"));
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] dec64 = cipher.doFinal(b64.decode(body64));
            logger.debug(new String(dec64));
            message.put("body", new String(dec64));
         } catch (UnsupportedEncodingException e) {
            throw new IamMessageException(e.getMessage());
         } catch (NoSuchAlgorithmException e) {
            throw new IamMessageException(e.getMessage());
         } catch (InvalidKeyException e) {
            throw new IamMessageException(e.getMessage());
         } catch (IllegalBlockSizeException e) {
            throw new IamMessageException(e.getMessage());
         } catch (NoSuchPaddingException e) {
            throw new IamMessageException(e.getMessage());
         } catch (InvalidAlgorithmParameterException e) {
            throw new IamMessageException(e.getMessage());
         } catch (BadPaddingException e) {
            throw new IamMessageException(e.getMessage());
         }
      } else {
         message.put("body", new String(b64.decode(body64)));
      }
      // We want to return the decoded context
      message.put("messageContext", new String(b64.decode(message.get("messageContext"))));
      return message;
   }

   private String getJson(JsonObject obj, String key) {
      JsonPrimitive p = obj.getAsJsonPrimitive(key);
      if (p==null) return null;
      return p.getAsString();
   }

   /* Build the object to sign.
      Note the messageContext and message body are base64 encoded here.  */

   private String buildSigMessage(Map msg, String body64) {
      String sigmsg = msg.get("contentType") + "\n";
      if (msg.get("keyId") != null) {
         sigmsg = sigmsg + msg.get("iv") + "\n" + msg.get("keyId") + "\n";
      }
      sigmsg = sigmsg + msg.get("messageContext") + "\n" +
                        msg.get("messageId") + "\n" +
                        msg.get("messageType") + "\n" +
                        msg.get("sender") + "\n" +
                        msg.get("signingCertUrl") + "\n" +
                        msg.get("timestamp") + "\n" +
                        msg.get("version") + "\n" +
                        body64 + "\n";
      logger.debug("sigmsg=[" + sigmsg + "]");
      return sigmsg;
   }

   /* Fetch a certificate from cache or a URL */

   public X509Certificate getCertificate(String certUrl) throws IamMessageException {
      
      FileInputStream file;
      X509Certificate cert = null;

      if (signingCerts.containsKey(certUrl)) return (X509Certificate) signingCerts.get(certUrl);

      if (certUrl.startsWith("file:")) {
         String certFile = certUrl.substring(5);
         logger.debug("certfile: " + certFile);
         try {
            file = new FileInputStream(certFile);
         } catch (IOException e) {
            throw new IamMessageException(e.getMessage());
         }
         try {
             CertificateFactory cf = CertificateFactory.getInstance("X.509");
             cert = (X509Certificate) cf.generateCertificate(file);
         } catch (CertificateException e) {
             throw new IamMessageException(e.getMessage());
         }

      } else { // assume http
         CloseableHttpClient client = HttpClients.createDefault();
         try {
            logger.debug("certurl: " + certUrl);
            HttpGet request = new HttpGet(certUrl);
            CloseableHttpResponse response = client.execute(request);
            HttpEntity entity = response.getEntity();
            if (entity == null) {
               client.close();
               throw new IamMessageException("certificate fetch exception");
            }
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(entity.getContent());
            client.close();
         } catch (IOException e) {
            try {
               client.close();
            } catch (IOException ee) {
            }
            throw new IamMessageException(e.getMessage());
         } catch (CertificateException e) {
            try {
               client.close();
            } catch (IOException ee) {
            }
            throw new IamMessageException(e.getMessage());
         }
      }
      if (cert!=null) signingCerts.put(certUrl, cert);
      return cert;
   }

   /* Read a private key from a PEM file */
   private RSAPrivateKey getPrivateKey(String keyUrl) throws IamMessageException {
      
      RSAPrivateKey key = null;

      if (signingKeys.containsKey(keyUrl)) return (RSAPrivateKey) signingKeys.get(keyUrl).key;

      String keyFile = keyUrl;
      if (keyUrl.startsWith("file:")) keyFile = keyUrl.substring(5);

      logger.debug("keyfile: " + keyFile);
      try {
         FileInputStream file = new FileInputStream(keyFile);
         byte[] keyBytes = new byte[file.available()];
         file.read(keyBytes);
         file.close();
         String keyString = new String(keyBytes, "UTF-8");
         // remove any leading, trailing test
         keyString = keyString.replaceAll("(-+BEGIN RSA PRIVATE KEY-+\\r?\\n|-+END RSA PRIVATE KEY-+\\r?\\n?)", "");
         keyBytes = b64.decode(keyString);

         PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
         KeyFactory keyFactory = KeyFactory.getInstance("RSA");
         key = (RSAPrivateKey) keyFactory.generatePrivate(spec);
      } catch (IOException e) {
         throw new IamMessageException(e.toString());
      } catch (InvalidKeySpecException e) {
         throw new IamMessageException(e.toString());
      } catch (NoSuchAlgorithmException e) {
         throw new IamMessageException(e.toString());
      }
      return key;
   }

   public void init(String configFile) throws IamMessageException, FileNotFoundException, IOException {
      logger.debug("IamMessage config: " + configFile);
         FileInputStream file = new FileInputStream(configFile);
         byte[] keyBytes = new byte[file.available()];
         file.read(keyBytes);
         file.close();
         String configString = new String(keyBytes, "UTF-8");

         JsonParser parser = new JsonParser();
         JsonObject obj = parser.parse(configString).getAsJsonObject();

         JsonArray certs = obj.getAsJsonArray("certs");
         Iterator it = certs.iterator();
         while (it.hasNext()) {
            JsonObject certobj = ((JsonObject)it.next()).getAsJsonObject();
            String id = getJson(certobj,"id");
            String url = getJson(certobj,"url");
            String keyfile = getJson(certobj,"keyfile");
            logger.debug("cert id = " + id);
            addSigningKey(id, url, keyfile);
         }

         JsonArray crypts = obj.getAsJsonArray("crypts");
         it = crypts.iterator();
         while (it.hasNext()) {
            JsonObject cryptobj = ((JsonObject)it.next()).getAsJsonObject();
            String id = getJson(cryptobj,"id");
            String key = getJson(cryptobj,"key");
            logger.debug("crypt id = " + id);
            addCryptKey(id, key);
         }
         ca_file = getJson(obj, "ca_file");
   }

}
