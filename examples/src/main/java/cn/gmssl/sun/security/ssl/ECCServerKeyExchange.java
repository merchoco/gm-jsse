package cn.gmssl.sun.security.ssl;

import cn.gmssl.crypto.impl.sm2.SM2Util;
import java.io.IOException;
import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;

public class ECCServerKeyExchange extends HandshakeMessage.ServerKeyExchange {
   private Signature signature;
   private byte[] signatureBytes;

   ECCServerKeyExchange(PrivateKey var1, PublicKey var2, RandomCookie var3, RandomCookie var4, X509Certificate var5, SecureRandom var6) throws GeneralSecurityException {
      this.signature = SM2Util.sm2Sign(var1, var2);
      this.signature.initSign(var1, var6);
      this.signature.update(var3.random_bytes);
      this.signature.update(var4.random_bytes);
      byte[] var7 = var5.getEncoded();
      int var8 = var7.length;
      this.signature.update((byte)(var8 >> 16 & 255));
      this.signature.update((byte)(var8 >> 8 & 255));
      this.signature.update((byte)(var8 & 255));
      this.signature.update(var7);
      this.signatureBytes = this.signature.sign();
   }

   ECCServerKeyExchange(HandshakeInStream var1) throws IOException, NoSuchAlgorithmException {
      this.signature = Signature.getInstance("SM3withSM2");
      this.signatureBytes = var1.getBytes16();
   }

   boolean verify(PublicKey var1, RandomCookie var2, RandomCookie var3, X509Certificate var4) throws GeneralSecurityException {
      this.signature.initVerify(var1);
      this.signature.update(var2.random_bytes);
      this.signature.update(var3.random_bytes);
      byte[] var5 = var4.getEncoded();
      int var6 = var5.length;
      this.signature.update((byte)(var6 >> 16 & 255));
      this.signature.update((byte)(var6 >> 8 & 255));
      this.signature.update((byte)(var6 & 255));
      this.signature.update(var5);
      boolean var7 = this.signature.verify(this.signatureBytes);
      return var7;
   }

   int messageLength() {
      return 2 + this.signatureBytes.length;
   }

   void send(HandshakeOutStream var1) throws IOException {
      var1.putBytes16(this.signatureBytes);
   }

   void print(PrintStream var1) throws IOException {
      var1.println("*** ECC ServerKeyExchange");
   }
}
