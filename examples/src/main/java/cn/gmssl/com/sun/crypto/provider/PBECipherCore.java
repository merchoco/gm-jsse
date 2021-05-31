package cn.gmssl.com.sun.crypto.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class PBECipherCore {
   private CipherCore cipher;
   private MessageDigest md;
   private int blkSize;
   private String algo = null;
   private byte[] salt = null;
   private int iCount = 10;

   PBECipherCore(String var1) throws NoSuchAlgorithmException, NoSuchPaddingException {
      this.algo = var1;
      if (this.algo.equals("DES")) {
         this.cipher = new CipherCore(new DESCrypt(), 8);
      } else {
         if (!this.algo.equals("DESede")) {
            throw new NoSuchAlgorithmException("No Cipher implementation for PBEWithMD5And" + this.algo);
         }

         this.cipher = new CipherCore(new DESedeCrypt(), 8);
      }

      this.cipher.setMode("CBC");
      this.cipher.setPadding("PKCS5Padding");
      this.md = MessageDigest.getInstance("MD5");
   }

   void setMode(String var1) throws NoSuchAlgorithmException {
      this.cipher.setMode(var1);
   }

   void setPadding(String var1) throws NoSuchPaddingException {
      this.cipher.setPadding(var1);
   }

   int getBlockSize() {
      return 8;
   }

   int getOutputSize(int var1) {
      return this.cipher.getOutputSize(var1);
   }

   byte[] getIV() {
      return this.cipher.getIV();
   }

   AlgorithmParameters getParameters() {
      AlgorithmParameters var1 = null;
      if (this.salt == null) {
         this.salt = new byte[8];
         SunJCE.RANDOM.nextBytes(this.salt);
      }

      PBEParameterSpec var2 = new PBEParameterSpec(this.salt, this.iCount);

      try {
         var1 = AlgorithmParameters.getInstance("PBEWithMD5And" + (this.algo.equalsIgnoreCase("DES") ? "DES" : "TripleDES"), "SunJCE");
      } catch (NoSuchAlgorithmException var5) {
         throw new RuntimeException("SunJCE called, but not configured");
      } catch (NoSuchProviderException var6) {
         throw new RuntimeException("SunJCE called, but not configured");
      }

      try {
         var1.init(var2);
         return var1;
      } catch (InvalidParameterSpecException var4) {
         throw new RuntimeException("PBEParameterSpec not supported");
      }
   }

   void init(int var1, Key var2, AlgorithmParameterSpec var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      if ((var1 == 2 || var1 == 4) && var3 == null) {
         throw new InvalidAlgorithmParameterException("Parameters missing");
      } else if (var2 != null && var2.getEncoded() != null && var2.getAlgorithm().regionMatches(true, 0, "PBE", 0, 3)) {
         if (var3 == null) {
            this.salt = new byte[8];
            var4.nextBytes(this.salt);
         } else {
            if (!(var3 instanceof PBEParameterSpec)) {
               throw new InvalidAlgorithmParameterException("Wrong parameter type: PBE expected");
            }

            this.salt = ((PBEParameterSpec)var3).getSalt();
            if (this.salt.length != 8) {
               throw new InvalidAlgorithmParameterException("Salt must be 8 bytes long");
            }

            this.iCount = ((PBEParameterSpec)var3).getIterationCount();
            if (this.iCount <= 0) {
               throw new InvalidAlgorithmParameterException("IterationCount must be a positive number");
            }
         }

         byte[] var5 = this.deriveCipherKey(var2);
         SecretKeySpec var6 = new SecretKeySpec(var5, 0, var5.length - 8, this.algo);
         IvParameterSpec var7 = new IvParameterSpec(var5, var5.length - 8, 8);
         this.cipher.init(var1, var6, (AlgorithmParameterSpec)var7, var4);
      } else {
         throw new InvalidKeyException("Missing password");
      }
   }

   private byte[] deriveCipherKey(Key var1) {
      byte[] var2 = null;
      byte[] var3 = var1.getEncoded();
      if (this.algo.equals("DES")) {
         byte[] var4 = new byte[var3.length + this.salt.length];
         System.arraycopy(var3, 0, var4, 0, var3.length);
         Arrays.fill(var3, (byte)0);
         System.arraycopy(this.salt, 0, var4, var3.length, this.salt.length);
         byte[] var5 = var4;

         for(int var6 = 0; var6 < this.iCount; ++var6) {
            this.md.update(var5);
            var5 = this.md.digest();
         }

         Arrays.fill(var4, (byte)0);
         var2 = var5;
      } else if (this.algo.equals("DESede")) {
         int var9;
         for(var9 = 0; var9 < 4 && this.salt[var9] == this.salt[var9 + 4]; ++var9) {
            ;
         }

         if (var9 == 4) {
            for(var9 = 0; var9 < 2; ++var9) {
               byte var10 = this.salt[var9];
               this.salt[var9] = this.salt[3 - var9];
               this.salt[2] = var10;
            }
         }

         Object var11 = null;
         Object var12 = null;
         Object var7 = null;
         var2 = new byte[32];

         for(var9 = 0; var9 < 2; ++var9) {
            byte[] var13 = new byte[this.salt.length / 2];
            System.arraycopy(this.salt, var9 * (this.salt.length / 2), var13, 0, var13.length);

            for(int var8 = 0; var8 < this.iCount; ++var8) {
               this.md.update(var13);
               this.md.update(var3);
               var13 = this.md.digest();
            }

            System.arraycopy(var13, 0, var2, var9 * 16, var13.length);
         }
      }

      return var2;
   }

   void init(int var1, Key var2, AlgorithmParameters var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      PBEParameterSpec var5 = null;
      if (var3 != null) {
         try {
            var5 = (PBEParameterSpec)var3.getParameterSpec(PBEParameterSpec.class);
         } catch (InvalidParameterSpecException var7) {
            throw new InvalidAlgorithmParameterException("Wrong parameter type: PBE expected");
         }
      }

      this.init(var1, var2, (AlgorithmParameterSpec)var5, var4);
   }

   byte[] update(byte[] var1, int var2, int var3) {
      return this.cipher.update(var1, var2, var3);
   }

   int update(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException {
      return this.cipher.update(var1, var2, var3, var4, var5);
   }

   byte[] doFinal(byte[] var1, int var2, int var3) throws IllegalBlockSizeException, BadPaddingException {
      return this.cipher.doFinal(var1, var2, var3);
   }

   int doFinal(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
      return this.cipher.doFinal(var1, var2, var3, var4, var5);
   }

   byte[] wrap(Key var1) throws IllegalBlockSizeException, InvalidKeyException {
      byte[] var2 = null;

      try {
         byte[] var3 = var1.getEncoded();
         if (var3 == null || var3.length == 0) {
            throw new InvalidKeyException("Cannot get an encoding of the key to be wrapped");
         }

         var2 = this.doFinal(var3, 0, var3.length);
      } catch (BadPaddingException var4) {
         ;
      }

      return var2;
   }

   Key unwrap(byte[] var1, String var2, int var3) throws InvalidKeyException, NoSuchAlgorithmException {
      byte[] var4;
      try {
         var4 = this.doFinal(var1, 0, var1.length);
      } catch (BadPaddingException var6) {
         throw new InvalidKeyException("The wrapped key is not padded correctly");
      } catch (IllegalBlockSizeException var7) {
         throw new InvalidKeyException("The wrapped key does not have the correct length");
      }

      return ConstructKeys.constructKey(var4, var2, var3);
   }
}
