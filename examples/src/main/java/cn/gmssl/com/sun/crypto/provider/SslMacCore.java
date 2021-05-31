package cn.gmssl.com.sun.crypto.provider;

import java.nio.ByteBuffer;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.MacSpi;
import javax.crypto.SecretKey;

final class SslMacCore {
   private final MessageDigest md;
   private final byte[] pad1;
   private final byte[] pad2;
   private boolean first;
   private byte[] secret;

   SslMacCore(String var1, byte[] var2, byte[] var3) throws NoSuchAlgorithmException {
      this.md = MessageDigest.getInstance(var1);
      this.pad1 = var2;
      this.pad2 = var3;
      this.first = true;
   }

   int getDigestLength() {
      return this.md.getDigestLength();
   }

   void init(Key var1, AlgorithmParameterSpec var2) throws InvalidKeyException, InvalidAlgorithmParameterException {
      if (var2 != null) {
         throw new InvalidAlgorithmParameterException("SslMac does not use parameters");
      } else if (!(var1 instanceof SecretKey)) {
         throw new InvalidKeyException("Secret key expected");
      } else {
         this.secret = var1.getEncoded();
         if (this.secret != null && this.secret.length != 0) {
            this.reset();
         } else {
            throw new InvalidKeyException("Missing key data");
         }
      }
   }

   void update(byte var1) {
      if (this.first) {
         this.md.update(this.secret);
         this.md.update(this.pad1);
         this.first = false;
      }

      this.md.update(var1);
   }

   void update(byte[] var1, int var2, int var3) {
      if (this.first) {
         this.md.update(this.secret);
         this.md.update(this.pad1);
         this.first = false;
      }

      this.md.update(var1, var2, var3);
   }

   void update(ByteBuffer var1) {
      if (this.first) {
         this.md.update(this.secret);
         this.md.update(this.pad1);
         this.first = false;
      }

      this.md.update(var1);
   }

   byte[] doFinal() {
      if (this.first) {
         this.md.update(this.secret);
         this.md.update(this.pad1);
      } else {
         this.first = true;
      }

      try {
         byte[] var1 = this.md.digest();
         this.md.update(this.secret);
         this.md.update(this.pad2);
         this.md.update(var1);
         this.md.digest(var1, 0, var1.length);
         return var1;
      } catch (DigestException var2) {
         throw new ProviderException(var2);
      }
   }

   void reset() {
      if (!this.first) {
         this.md.reset();
         this.first = true;
      }

   }

   public static final class SslMacMD5 extends MacSpi {
      private final SslMacCore core;
      static final byte[] md5Pad1 = TlsPrfGenerator.genPad((byte)54, 48);
      static final byte[] md5Pad2 = TlsPrfGenerator.genPad((byte)92, 48);

      public SslMacMD5() throws NoSuchAlgorithmException {
         this.core = new SslMacCore("MD5", md5Pad1, md5Pad2);
      }

      protected int engineGetMacLength() {
         return this.core.getDigestLength();
      }

      protected void engineInit(Key var1, AlgorithmParameterSpec var2) throws InvalidKeyException, InvalidAlgorithmParameterException {
         this.core.init(var1, var2);
      }

      protected void engineUpdate(byte var1) {
         this.core.update(var1);
      }

      protected void engineUpdate(byte[] var1, int var2, int var3) {
         this.core.update(var1, var2, var3);
      }

      protected void engineUpdate(ByteBuffer var1) {
         this.core.update(var1);
      }

      protected byte[] engineDoFinal() {
         return this.core.doFinal();
      }

      protected void engineReset() {
         this.core.reset();
      }
   }

   public static final class SslMacSHA1 extends MacSpi {
      private final SslMacCore core;
      static final byte[] shaPad1 = TlsPrfGenerator.genPad((byte)54, 40);
      static final byte[] shaPad2 = TlsPrfGenerator.genPad((byte)92, 40);

      public SslMacSHA1() throws NoSuchAlgorithmException {
         this.core = new SslMacCore("SHA", shaPad1, shaPad2);
      }

      protected int engineGetMacLength() {
         return this.core.getDigestLength();
      }

      protected void engineInit(Key var1, AlgorithmParameterSpec var2) throws InvalidKeyException, InvalidAlgorithmParameterException {
         this.core.init(var1, var2);
      }

      protected void engineUpdate(byte var1) {
         this.core.update(var1);
      }

      protected void engineUpdate(byte[] var1, int var2, int var3) {
         this.core.update(var1, var2, var3);
      }

      protected void engineUpdate(ByteBuffer var1) {
         this.core.update(var1);
      }

      protected byte[] engineDoFinal() {
         return this.core.doFinal();
      }

      protected void engineReset() {
         this.core.reset();
      }
   }
}
