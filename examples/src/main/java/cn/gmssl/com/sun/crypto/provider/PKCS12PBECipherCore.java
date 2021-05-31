package cn.gmssl.com.sun.crypto.provider;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class PKCS12PBECipherCore {
   private CipherCore cipher;
   private int blockSize;
   private int keySize;
   private String algo = null;
   private byte[] salt = null;
   private int iCount = 0;
   private static final int DEFAULT_SALT_LENGTH = 20;
   private static final int DEFAULT_COUNT = 1024;
   static final int CIPHER_KEY = 1;
   static final int CIPHER_IV = 2;
   static final int MAC_KEY = 3;

   static byte[] derive(char[] var0, byte[] var1, int var2, int var3, int var4) {
      int var5 = var0.length * 2;
      if (var5 != 0) {
         var5 += 2;
      }

      byte[] var6 = new byte[var5];
      int var7 = 0;

      for(int var8 = 0; var7 < var0.length; var8 += 2) {
         var6[var8] = (byte)(var0[var7] >>> 8 & 255);
         var6[var8 + 1] = (byte)(var0[var7] & 255);
         ++var7;
      }

      byte var25 = 64;
      byte var26 = 20;
      int var9 = roundup(var3, var26) / var26;
      byte[] var10 = new byte[var25];
      int var11 = roundup(var1.length, var25);
      int var12 = roundup(var6.length, var25);
      byte[] var13 = new byte[var11 + var12];
      byte[] var14 = new byte[var3];
      Arrays.fill(var10, (byte)var4);
      concat(var1, var13, 0, var11);
      concat(var6, var13, var11, var12);

      try {
         MessageDigest var15 = MessageDigest.getInstance("SHA1");
         byte[] var17 = new byte[var25];
         byte[] var18 = new byte[var25];
         int var19 = 0;

         while(true) {
            var15.update(var10);
            var15.update(var13);
            byte[] var16 = var15.digest();

            for(int var20 = 1; var20 < var2; ++var20) {
               var16 = var15.digest(var16);
            }

            System.arraycopy(var16, 0, var14, var26 * var19, Math.min(var3, var26));
            if (var19 + 1 == var9) {
               return var14;
            }

            concat(var16, var17, 0, var17.length);
            BigInteger var27 = (new BigInteger(1, var17)).add(BigInteger.ONE);

            for(int var21 = 0; var21 < var13.length; var21 += var25) {
               if (var18.length != var25) {
                  var18 = new byte[var25];
               }

               System.arraycopy(var13, var21, var18, 0, var25);
               BigInteger var22 = new BigInteger(1, var18);
               var22 = var22.add(var27);
               var18 = var22.toByteArray();
               int var23 = var18.length - var25;
               if (var23 >= 0) {
                  System.arraycopy(var18, var23, var13, var21, var25);
               } else if (var23 < 0) {
                  Arrays.fill(var13, var21, var21 + -var23, (byte)0);
                  System.arraycopy(var18, 0, var13, var21 + -var23, var18.length);
               }
            }

            ++var19;
            var3 -= var26;
         }
      } catch (Exception var24) {
         throw new RuntimeException("internal error: " + var24);
      }
   }

   private static int roundup(int var0, int var1) {
      return (var0 + (var1 - 1)) / var1 * var1;
   }

   private static void concat(byte[] var0, byte[] var1, int var2, int var3) {
      int var4 = var3 / var0.length;
      int var6 = 0;

      int var5;
      for(var5 = 0; var6 < var4; var5 += var0.length) {
         System.arraycopy(var0, 0, var1, var5 + var2, var0.length);
         ++var6;
      }

      System.arraycopy(var0, 0, var1, var5 + var2, var3 - var5);
   }

   PKCS12PBECipherCore(String var1, int var2) throws NoSuchAlgorithmException {
      this.algo = var1;
      Object var3 = null;
      if (this.algo.equals("DESede")) {
         var3 = new DESedeCrypt();
      } else {
         if (!this.algo.equals("RC2")) {
            throw new NoSuchAlgorithmException("No Cipher implementation for PBEWithSHA1And" + this.algo);
         }

         var3 = new RC2Crypt();
      }

      this.blockSize = ((SymmetricCipher)var3).getBlockSize();
      this.cipher = new CipherCore((SymmetricCipher)var3, this.blockSize);
      this.cipher.setMode("CBC");

      try {
         this.cipher.setPadding("PKCS5Padding");
      } catch (NoSuchPaddingException var5) {
         ;
      }

      this.keySize = var2;
   }

   void implSetMode(String var1) throws NoSuchAlgorithmException {
      if (var1 != null && !var1.equalsIgnoreCase("CBC")) {
         throw new NoSuchAlgorithmException("Invalid cipher mode: " + var1);
      }
   }

   void implSetPadding(String var1) throws NoSuchPaddingException {
      if (var1 != null && !var1.equalsIgnoreCase("PKCS5Padding")) {
         throw new NoSuchPaddingException("Invalid padding scheme: " + var1);
      }
   }

   int implGetBlockSize() {
      return this.blockSize;
   }

   int implGetOutputSize(int var1) {
      return this.cipher.getOutputSize(var1);
   }

   byte[] implGetIV() {
      return this.cipher.getIV();
   }

   AlgorithmParameters implGetParameters() {
      AlgorithmParameters var1 = null;
      if (this.salt == null) {
         this.salt = new byte[20];
         SunJCE.RANDOM.nextBytes(this.salt);
         this.iCount = 1024;
      }

      PBEParameterSpec var2 = new PBEParameterSpec(this.salt, this.iCount);

      try {
         var1 = AlgorithmParameters.getInstance("PBEWithSHA1And" + (this.algo.equalsIgnoreCase("RC2") ? "RC2_40" : this.algo), "SunJCE");
      } catch (GeneralSecurityException var5) {
         throw new RuntimeException("SunJCE provider is not configured properly");
      }

      try {
         var1.init(var2);
         return var1;
      } catch (InvalidParameterSpecException var4) {
         throw new RuntimeException("PBEParameterSpec not supported");
      }
   }

   void implInit(int var1, Key var2, AlgorithmParameterSpec var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      Object var5 = null;
      this.salt = null;
      this.iCount = 0;
      char[] var10;
      byte[] var11;
      if (var2 instanceof javax.crypto.interfaces.PBEKey) {
         javax.crypto.interfaces.PBEKey var6 = (javax.crypto.interfaces.PBEKey)var2;
         var10 = var6.getPassword();
         this.salt = var6.getSalt();
         this.iCount = var6.getIterationCount();
      } else {
         if (!(var2 instanceof SecretKey)) {
            throw new InvalidKeyException("SecretKey of PBE type required");
         }

         var11 = var2.getEncoded();
         if (var11 == null || !var2.getAlgorithm().regionMatches(true, 0, "PBE", 0, 3)) {
            throw new InvalidKeyException("Missing password");
         }

         var10 = new char[var11.length];

         for(int var7 = 0; var7 < var10.length; ++var7) {
            var10[var7] = (char)(var11[var7] & 127);
         }
      }

      if (var1 != 2 && var1 != 4 || var3 != null || this.salt != null && this.iCount != 0) {
         if (var3 == null) {
            if (this.salt == null) {
               this.salt = new byte[20];
               if (var4 != null) {
                  var4.nextBytes(this.salt);
               } else {
                  SunJCE.RANDOM.nextBytes(this.salt);
               }
            }

            if (this.iCount == 0) {
               this.iCount = 1024;
            }
         } else {
            if (!(var3 instanceof PBEParameterSpec)) {
               throw new InvalidAlgorithmParameterException("PBEParameterSpec type required");
            }

            PBEParameterSpec var12 = (PBEParameterSpec)var3;
            if (this.salt != null) {
               if (!Arrays.equals(this.salt, var12.getSalt())) {
                  throw new InvalidAlgorithmParameterException("Inconsistent value of salt between key and params");
               }
            } else {
               this.salt = var12.getSalt();
            }

            if (this.iCount != 0) {
               if (this.iCount != var12.getIterationCount()) {
                  throw new InvalidAlgorithmParameterException("Different iteration count between key and params");
               }
            } else {
               this.iCount = var12.getIterationCount();
            }
         }

         if (this.salt.length < 8) {
            throw new InvalidAlgorithmParameterException("Salt must be at least 8 bytes long");
         } else if (this.iCount <= 0) {
            throw new InvalidAlgorithmParameterException("IterationCount must be a positive number");
         } else {
            var11 = derive(var10, this.salt, this.iCount, this.keySize, 1);
            SecretKeySpec var13 = new SecretKeySpec(var11, this.algo);
            byte[] var8 = derive(var10, this.salt, this.iCount, 8, 2);
            IvParameterSpec var9 = new IvParameterSpec(var8, 0, 8);
            this.cipher.init(var1, var13, (AlgorithmParameterSpec)var9, var4);
         }
      } else {
         throw new InvalidAlgorithmParameterException("Parameters missing");
      }
   }

   void implInit(int var1, Key var2, AlgorithmParameters var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      AlgorithmParameterSpec var5 = null;
      if (var3 != null) {
         try {
            var5 = var3.getParameterSpec(PBEParameterSpec.class);
         } catch (InvalidParameterSpecException var7) {
            throw new InvalidAlgorithmParameterException("requires PBE parameters");
         }
      }

      this.implInit(var1, var2, var5, var4);
   }

   void implInit(int var1, Key var2, SecureRandom var3) throws InvalidKeyException {
      try {
         this.implInit(var1, var2, (AlgorithmParameterSpec)null, var3);
      } catch (InvalidAlgorithmParameterException var5) {
         throw new InvalidKeyException("requires PBE parameters");
      }
   }

   byte[] implUpdate(byte[] var1, int var2, int var3) {
      return this.cipher.update(var1, var2, var3);
   }

   int implUpdate(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException {
      return this.cipher.update(var1, var2, var3, var4, var5);
   }

   byte[] implDoFinal(byte[] var1, int var2, int var3) throws IllegalBlockSizeException, BadPaddingException {
      return this.cipher.doFinal(var1, var2, var3);
   }

   int implDoFinal(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
      return this.cipher.doFinal(var1, var2, var3, var4, var5);
   }

   int implGetKeySize(Key var1) throws InvalidKeyException {
      return this.keySize;
   }

   byte[] implWrap(Key var1) throws IllegalBlockSizeException, InvalidKeyException {
      return this.cipher.wrap(var1);
   }

   Key implUnwrap(byte[] var1, String var2, int var3) throws InvalidKeyException, NoSuchAlgorithmException {
      return this.cipher.unwrap(var1, var2, var3);
   }

   public static final class PBEWithSHA1AndDESede extends CipherSpi {
      private final PKCS12PBECipherCore core = new PKCS12PBECipherCore("DESede", 24);

      public PBEWithSHA1AndDESede() throws NoSuchAlgorithmException {
      }

      protected byte[] engineDoFinal(byte[] var1, int var2, int var3) throws IllegalBlockSizeException, BadPaddingException {
         return this.core.implDoFinal(var1, var2, var3);
      }

      protected int engineDoFinal(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
         return this.core.implDoFinal(var1, var2, var3, var4, var5);
      }

      protected int engineGetBlockSize() {
         return this.core.implGetBlockSize();
      }

      protected byte[] engineGetIV() {
         return this.core.implGetIV();
      }

      protected int engineGetKeySize(Key var1) throws InvalidKeyException {
         return this.core.implGetKeySize(var1);
      }

      protected int engineGetOutputSize(int var1) {
         return this.core.implGetOutputSize(var1);
      }

      protected AlgorithmParameters engineGetParameters() {
         return this.core.implGetParameters();
      }

      protected void engineInit(int var1, Key var2, AlgorithmParameterSpec var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
         this.core.implInit(var1, var2, var3, var4);
      }

      protected void engineInit(int var1, Key var2, AlgorithmParameters var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
         this.core.implInit(var1, var2, var3, var4);
      }

      protected void engineInit(int var1, Key var2, SecureRandom var3) throws InvalidKeyException {
         this.core.implInit(var1, var2, var3);
      }

      protected void engineSetMode(String var1) throws NoSuchAlgorithmException {
         this.core.implSetMode(var1);
      }

      protected void engineSetPadding(String var1) throws NoSuchPaddingException {
         this.core.implSetPadding(var1);
      }

      protected Key engineUnwrap(byte[] var1, String var2, int var3) throws InvalidKeyException, NoSuchAlgorithmException {
         return this.core.implUnwrap(var1, var2, var3);
      }

      protected byte[] engineUpdate(byte[] var1, int var2, int var3) {
         return this.core.implUpdate(var1, var2, var3);
      }

      protected int engineUpdate(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException {
         return this.core.implUpdate(var1, var2, var3, var4, var5);
      }

      protected byte[] engineWrap(Key var1) throws IllegalBlockSizeException, InvalidKeyException {
         return this.core.implWrap(var1);
      }
   }

   public static final class PBEWithSHA1AndRC2_40 extends CipherSpi {
      private final PKCS12PBECipherCore core = new PKCS12PBECipherCore("RC2", 5);

      public PBEWithSHA1AndRC2_40() throws NoSuchAlgorithmException {
      }

      protected byte[] engineDoFinal(byte[] var1, int var2, int var3) throws IllegalBlockSizeException, BadPaddingException {
         return this.core.implDoFinal(var1, var2, var3);
      }

      protected int engineDoFinal(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
         return this.core.implDoFinal(var1, var2, var3, var4, var5);
      }

      protected int engineGetBlockSize() {
         return this.core.implGetBlockSize();
      }

      protected byte[] engineGetIV() {
         return this.core.implGetIV();
      }

      protected int engineGetKeySize(Key var1) throws InvalidKeyException {
         return this.core.implGetKeySize(var1);
      }

      protected int engineGetOutputSize(int var1) {
         return this.core.implGetOutputSize(var1);
      }

      protected AlgorithmParameters engineGetParameters() {
         return this.core.implGetParameters();
      }

      protected void engineInit(int var1, Key var2, AlgorithmParameterSpec var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
         this.core.implInit(var1, var2, var3, var4);
      }

      protected void engineInit(int var1, Key var2, AlgorithmParameters var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
         this.core.implInit(var1, var2, var3, var4);
      }

      protected void engineInit(int var1, Key var2, SecureRandom var3) throws InvalidKeyException {
         this.core.implInit(var1, var2, var3);
      }

      protected void engineSetMode(String var1) throws NoSuchAlgorithmException {
         this.core.implSetMode(var1);
      }

      protected void engineSetPadding(String var1) throws NoSuchPaddingException {
         this.core.implSetPadding(var1);
      }

      protected Key engineUnwrap(byte[] var1, String var2, int var3) throws InvalidKeyException, NoSuchAlgorithmException {
         return this.core.implUnwrap(var1, var2, var3);
      }

      protected byte[] engineUpdate(byte[] var1, int var2, int var3) {
         return this.core.implUpdate(var1, var2, var3);
      }

      protected int engineUpdate(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException {
         return this.core.implUpdate(var1, var2, var3, var4, var5);
      }

      protected byte[] engineWrap(Key var1) throws IllegalBlockSizeException, InvalidKeyException {
         return this.core.implWrap(var1);
      }
   }
}
