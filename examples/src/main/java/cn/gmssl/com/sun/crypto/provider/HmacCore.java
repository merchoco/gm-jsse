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
import java.util.Arrays;
import javax.crypto.MacSpi;
import javax.crypto.SecretKey;

final class HmacCore implements Cloneable {
   private final MessageDigest md;
   private final byte[] k_ipad;
   private final byte[] k_opad;
   private boolean first;
   private final int blockLen;

   HmacCore(MessageDigest var1, int var2) {
      this.md = var1;
      this.blockLen = var2;
      this.k_ipad = new byte[this.blockLen];
      this.k_opad = new byte[this.blockLen];
      this.first = true;
   }

   HmacCore(String var1, int var2) throws NoSuchAlgorithmException {
      this(MessageDigest.getInstance(var1), var2);
   }

   private HmacCore(HmacCore var1) throws CloneNotSupportedException {
      this.md = (MessageDigest)var1.md.clone();
      this.blockLen = var1.blockLen;
      this.k_ipad = (byte[])var1.k_ipad.clone();
      this.k_opad = (byte[])var1.k_opad.clone();
      this.first = var1.first;
   }

   int getDigestLength() {
      return this.md.getDigestLength();
   }

   void init(Key var1, AlgorithmParameterSpec var2) throws InvalidKeyException, InvalidAlgorithmParameterException {
      if (var2 != null) {
         throw new InvalidAlgorithmParameterException("HMAC does not use parameters");
      } else if (!(var1 instanceof SecretKey)) {
         throw new InvalidKeyException("Secret key expected");
      } else {
         byte[] var3 = var1.getEncoded();
         if (var3 == null) {
            throw new InvalidKeyException("Missing key data");
         } else {
            if (var3.length > this.blockLen) {
               byte[] var4 = this.md.digest(var3);
               Arrays.fill(var3, (byte)0);
               var3 = var4;
            }

            for(int var6 = 0; var6 < this.blockLen; ++var6) {
               byte var5 = var6 < var3.length ? var3[var6] : 0;
               this.k_ipad[var6] = (byte)(var5 ^ 54);
               this.k_opad[var6] = (byte)(var5 ^ 92);
            }

            Arrays.fill(var3, (byte)0);
            Object var7 = null;
            this.reset();
         }
      }
   }

   void update(byte var1) {
      if (this.first) {
         this.md.update(this.k_ipad);
         this.first = false;
      }

      this.md.update(var1);
   }

   void update(byte[] var1, int var2, int var3) {
      if (this.first) {
         this.md.update(this.k_ipad);
         this.first = false;
      }

      this.md.update(var1, var2, var3);
   }

   void update(ByteBuffer var1) {
      if (this.first) {
         this.md.update(this.k_ipad);
         this.first = false;
      }

      this.md.update(var1);
   }

   byte[] doFinal() {
      if (this.first) {
         this.md.update(this.k_ipad);
      } else {
         this.first = true;
      }

      try {
         byte[] var1 = this.md.digest();
         this.md.update(this.k_opad);
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

   public Object clone() throws CloneNotSupportedException {
      return new HmacCore(this);
   }

   public static final class HmacSHA256 extends MacSpi implements Cloneable {
      private final HmacCore core;

      public HmacSHA256() throws NoSuchAlgorithmException {
         this.core = new HmacCore("SHA-256", 64);
      }

      private HmacSHA256(HmacCore.HmacSHA256 var1) throws CloneNotSupportedException {
         this.core = (HmacCore)var1.core.clone();
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

      public Object clone() throws CloneNotSupportedException {
         return new HmacCore.HmacSHA256(this);
      }
   }

   public static final class HmacSHA384 extends MacSpi implements Cloneable {
      private final HmacCore core;

      public HmacSHA384() throws NoSuchAlgorithmException {
         this.core = new HmacCore("SHA-384", 128);
      }

      private HmacSHA384(HmacCore.HmacSHA384 var1) throws CloneNotSupportedException {
         this.core = (HmacCore)var1.core.clone();
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

      public Object clone() throws CloneNotSupportedException {
         return new HmacCore.HmacSHA384(this);
      }
   }

   public static final class HmacSHA512 extends MacSpi implements Cloneable {
      private final HmacCore core;

      public HmacSHA512() throws NoSuchAlgorithmException {
         this.core = new HmacCore("SHA-512", 128);
      }

      private HmacSHA512(HmacCore.HmacSHA512 var1) throws CloneNotSupportedException {
         this.core = (HmacCore)var1.core.clone();
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

      public Object clone() throws CloneNotSupportedException {
         return new HmacCore.HmacSHA512(this);
      }
   }
}
