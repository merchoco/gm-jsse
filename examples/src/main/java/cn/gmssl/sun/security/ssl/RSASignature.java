package cn.gmssl.sun.security.ssl;

import java.security.DigestException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;

public final class RSASignature extends SignatureSpi {
   private final Signature rawRsa = JsseJce.getSignature("NONEwithRSA");
   private MessageDigest md5;
   private MessageDigest sha;
   private boolean isReset = true;

   public RSASignature() throws NoSuchAlgorithmException {
   }

   static Signature getInstance() throws NoSuchAlgorithmException {
      return JsseJce.getSignature("MD5andSHA1withRSA");
   }

   static Signature getInternalInstance() throws NoSuchAlgorithmException, NoSuchProviderException {
      return Signature.getInstance("MD5andSHA1withRSA", "SunJSSE");
   }

   static void setHashes(Signature var0, MessageDigest var1, MessageDigest var2) {
      var0.setParameter("hashes", new MessageDigest[]{var1, var2});
   }

   private void reset() {
      if (!this.isReset) {
         this.md5.reset();
         this.sha.reset();
         this.isReset = true;
      }

   }

   private static void checkNull(Key var0) throws InvalidKeyException {
      if (var0 == null) {
         throw new InvalidKeyException("Key must not be null");
      }
   }

   protected void engineInitVerify(PublicKey var1) throws InvalidKeyException {
      checkNull(var1);
      this.reset();
      this.rawRsa.initVerify(var1);
   }

   protected void engineInitSign(PrivateKey var1) throws InvalidKeyException {
      this.engineInitSign(var1, (SecureRandom)null);
   }

   protected void engineInitSign(PrivateKey var1, SecureRandom var2) throws InvalidKeyException {
      checkNull(var1);
      this.reset();
      this.rawRsa.initSign(var1, var2);
   }

   private void initDigests() {
      if (this.md5 == null) {
         this.md5 = JsseJce.getMD5();
         this.sha = JsseJce.getSHA();
      }

   }

   protected void engineUpdate(byte var1) {
      this.initDigests();
      this.isReset = false;
      this.md5.update(var1);
      this.sha.update(var1);
   }

   protected void engineUpdate(byte[] var1, int var2, int var3) {
      this.initDigests();
      this.isReset = false;
      this.md5.update(var1, var2, var3);
      this.sha.update(var1, var2, var3);
   }

   private byte[] getDigest() throws SignatureException {
      try {
         this.initDigests();
         byte[] var1 = new byte[36];
         this.md5.digest(var1, 0, 16);
         this.sha.digest(var1, 16, 20);
         this.isReset = true;
         return var1;
      } catch (DigestException var2) {
         throw new SignatureException(var2);
      }
   }

   protected byte[] engineSign() throws SignatureException {
      this.rawRsa.update(this.getDigest());
      return this.rawRsa.sign();
   }

   protected boolean engineVerify(byte[] var1) throws SignatureException {
      return this.engineVerify(var1, 0, var1.length);
   }

   protected boolean engineVerify(byte[] var1, int var2, int var3) throws SignatureException {
      this.rawRsa.update(this.getDigest());
      return this.rawRsa.verify(var1, var2, var3);
   }

   protected void engineSetParameter(String var1, Object var2) throws InvalidParameterException {
      if (!var1.equals("hashes")) {
         throw new InvalidParameterException("Parameter not supported: " + var1);
      } else if (!(var2 instanceof MessageDigest[])) {
         throw new InvalidParameterException("value must be MessageDigest[]");
      } else {
         MessageDigest[] var3 = (MessageDigest[])var2;
         this.md5 = var3[0];
         this.sha = var3[1];
      }
   }

   protected Object engineGetParameter(String var1) throws InvalidParameterException {
      throw new InvalidParameterException("Parameters not supported");
   }
}
