package cn.gmssl.sun.security.ssl;

import cn.gmssl.sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec;
import java.io.IOException;
import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLKeyException;
import javax.net.ssl.SSLProtocolException;

final class ECCClientKeyExchange extends HandshakeMessage {
   private ProtocolVersion protocolVersion;
   SecretKey preMaster;
   private byte[] encrypted;

   ECCClientKeyExchange(ProtocolVersion var1, ProtocolVersion var2, SecureRandom var3, PublicKey var4) throws IOException {
      if (!var4.getAlgorithm().equals("EC") && !var4.getAlgorithm().equals("SM2")) {
         throw new SSLKeyException("Public key not of type EC");
      } else {
         this.protocolVersion = var1;
         byte var5;
         byte var6;
         if (var2.v >= ProtocolVersion.TLS11.v) {
            var5 = var2.major;
            var6 = var2.minor;
         } else {
            var5 = var1.major;
            var6 = var1.minor;
         }

         try {
            String var7 = var1.v >= ProtocolVersion.TLS12.v ? "SunTls12RsaPremasterSecret" : "SunTlsRsaPremasterSecret";
            KeyGenerator var8 = JsseJce.getKeyGenerator(var7);
            var8.init(new TlsRsaPremasterSecretParameterSpec(var5, var6), var3);
            this.preMaster = var8.generateKey();
            Cipher var9 = JsseJce.getCipher("SM2");
            var9.init(3, var4, var3);
            this.encrypted = var9.wrap(this.preMaster);
         } catch (GeneralSecurityException var10) {
            throw (SSLKeyException)(new SSLKeyException("SM2 premaster secret error")).initCause(var10);
         } catch (Exception var11) {
            throw new RuntimeException(var11);
         }
      }
   }

   ECCClientKeyExchange(ProtocolVersion var1, ProtocolVersion var2, SecureRandom var3, HandshakeInStream var4, int var5, PrivateKey var6, StringBuilder var7) throws IOException {
      if (!var6.getAlgorithm().equals("EC") && !var6.getAlgorithm().equals("SM2")) {
         throw new SSLKeyException("Private key not of type EC");
      } else {
         if (var1.v >= ProtocolVersion.TLS10.v) {
            this.encrypted = var4.getBytes16();
         } else {
            this.encrypted = new byte[var5];
            if (var4.read(this.encrypted) != var5) {
               throw new SSLProtocolException("SSL: read PreMasterSecret: short read");
            }
         }

         try {
            Cipher var8 = JsseJce.getCipher("SM2");
            var8.init(4, var6);
            this.preMaster = (SecretKey)var8.unwrap(this.encrypted, "TlsRsaPremasterSecret", 3);
         } catch (Exception var9) {
            this.preMaster = this.polishPreMasterSecretKey(var1, var2, var3, (SecretKey)null, var9);
         }

      }
   }

   private SecretKey polishPreMasterSecretKey(ProtocolVersion var1, ProtocolVersion var2, SecureRandom var3, SecretKey var4, Exception var5) {
      this.protocolVersion = var2;
      if (var5 == null && var4 != null) {
         byte[] var6 = var4.getEncoded();
         if (var6 == null) {
            if (debug != null && Debug.isOn("handshake")) {
               System.out.println("unable to get the plaintext of the premaster secret");
            }

            return var4;
         }

         if (var6.length == 48) {
            if (var2.major == var6[0] && var2.minor == var6[1]) {
               return var4;
            }

            if (var2.v <= ProtocolVersion.TLS10.v && var1.major == var6[0] && var1.minor == var6[1]) {
               this.protocolVersion = var1;
               return var4;
            }

            if (debug != null && Debug.isOn("handshake")) {
               System.out.println("Mismatching Protocol Versions, ClientHello.client_version is " + var2 + ", while PreMasterSecret.client_version is " + ProtocolVersion.valueOf(var6[0], var6[1]));
            }
         } else if (debug != null && Debug.isOn("handshake")) {
            System.out.println("incorrect length of premaster secret: " + var6.length);
         }
      }

      if (debug != null && Debug.isOn("handshake")) {
         if (var5 != null) {
            System.out.println("Error decrypting premaster secret:");
            var5.printStackTrace(System.out);
         }

         System.out.println("Generating random secret");
      }

      return generateDummySecret(var2);
   }

   static SecretKey generateDummySecret(ProtocolVersion var0) {
      try {
         String var1 = var0.v >= ProtocolVersion.TLS12.v ? "SunTls12RsaPremasterSecret" : "SunTlsRsaPremasterSecret";
         KeyGenerator var2 = JsseJce.getKeyGenerator(var1);
         var2.init(new TlsRsaPremasterSecretParameterSpec(var0.major, var0.minor));
         return var2.generateKey();
      } catch (GeneralSecurityException var3) {
         throw new RuntimeException("Could not generate dummy secret", var3);
      }
   }

   int messageType() {
      return 16;
   }

   int messageLength() {
      return this.protocolVersion.v >= ProtocolVersion.TLS10.v ? this.encrypted.length + 2 : this.encrypted.length;
   }

   void send(HandshakeOutStream var1) throws IOException {
      if (this.protocolVersion.v >= ProtocolVersion.TLS10.v) {
         var1.putBytes16(this.encrypted);
      } else {
         var1.write(this.encrypted);
      }

   }

   void print(PrintStream var1) throws IOException {
      var1.println("*** ClientKeyExchange, RSA PreMasterSecret, " + this.protocolVersion);
   }
}
