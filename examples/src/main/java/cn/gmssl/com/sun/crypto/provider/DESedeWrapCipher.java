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
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

public final class DESedeWrapCipher extends CipherSpi {
   private static final byte[] IV2 = new byte[]{74, -35, -94, 44, 121, -24, 33, 5};
   private FeedbackCipher cipher = new CipherBlockChaining(new DESedeCrypt());
   private byte[] iv = null;
   private Key cipherKey = null;
   private boolean decrypting = false;

   protected void engineSetMode(String var1) throws NoSuchAlgorithmException {
      if (!var1.equalsIgnoreCase("CBC")) {
         throw new NoSuchAlgorithmException(var1 + " cannot be used");
      }
   }

   protected void engineSetPadding(String var1) throws NoSuchPaddingException {
      if (!var1.equalsIgnoreCase("NoPadding")) {
         throw new NoSuchPaddingException(var1 + " cannot be used");
      }
   }

   protected int engineGetBlockSize() {
      return 8;
   }

   protected int engineGetOutputSize(int var1) {
      boolean var2 = false;
      int var3;
      if (this.decrypting) {
         var3 = var1 - 16;
      } else {
         var3 = var1 + 16;
      }

      return var3 < 0 ? 0 : var3;
   }

   protected byte[] engineGetIV() {
      return this.iv == null ? null : (byte[])this.iv.clone();
   }

   protected void engineInit(int var1, Key var2, SecureRandom var3) throws InvalidKeyException {
      try {
         this.engineInit(var1, var2, (AlgorithmParameterSpec)null, var3);
      } catch (InvalidAlgorithmParameterException var6) {
         InvalidKeyException var5 = new InvalidKeyException("Parameters required");
         var5.initCause(var6);
         throw var5;
      }
   }

   protected void engineInit(int var1, Key var2, AlgorithmParameterSpec var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      Object var5 = null;
      byte[] var6;
      if (var1 == 3) {
         this.decrypting = false;
         if (var3 == null) {
            this.iv = new byte[8];
            if (var4 == null) {
               var4 = SunJCE.RANDOM;
            }

            var4.nextBytes(this.iv);
         } else {
            if (!(var3 instanceof IvParameterSpec)) {
               throw new InvalidAlgorithmParameterException("Wrong parameter type: IV expected");
            }

            this.iv = ((IvParameterSpec)var3).getIV();
         }

         var6 = this.iv;
      } else {
         if (var1 != 4) {
            throw new UnsupportedOperationException("This cipher can only be used for key wrapping and unwrapping");
         }

         if (var3 != null) {
            throw new InvalidAlgorithmParameterException("No parameter accepted for unwrapping keys");
         }

         this.iv = null;
         this.decrypting = true;
         var6 = IV2;
      }

      this.cipher.init(this.decrypting, var2.getAlgorithm(), var2.getEncoded(), var6);
      this.cipherKey = var2;
   }

   protected void engineInit(int var1, Key var2, AlgorithmParameters var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      IvParameterSpec var5 = null;
      if (var3 != null) {
         try {
            DESedeParameters var6 = new DESedeParameters();
            var6.engineInit(var3.getEncoded());
            var5 = (IvParameterSpec)var6.engineGetParameterSpec(IvParameterSpec.class);
         } catch (Exception var8) {
            InvalidAlgorithmParameterException var7 = new InvalidAlgorithmParameterException("Wrong parameter type: IV expected");
            var7.initCause(var8);
            throw var7;
         }
      }

      this.engineInit(var1, var2, (AlgorithmParameterSpec)var5, var4);
   }

   protected byte[] engineUpdate(byte[] var1, int var2, int var3) {
      throw new IllegalStateException("Cipher has not been initialized");
   }

   protected int engineUpdate(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException {
      throw new IllegalStateException("Cipher has not been initialized");
   }

   protected byte[] engineDoFinal(byte[] var1, int var2, int var3) throws IllegalBlockSizeException, BadPaddingException {
      throw new IllegalStateException("Cipher has not been initialized");
   }

   protected int engineDoFinal(byte[] var1, int var2, int var3, byte[] var4, int var5) throws IllegalBlockSizeException, ShortBufferException, BadPaddingException {
      throw new IllegalStateException("Cipher has not been initialized");
   }

   protected AlgorithmParameters engineGetParameters() {
      AlgorithmParameters var1 = null;
      if (this.iv != null) {
         String var2 = this.cipherKey.getAlgorithm();

         try {
            var1 = AlgorithmParameters.getInstance(var2, "SunJCE");
         } catch (NoSuchAlgorithmException var5) {
            throw new RuntimeException("Cannot find " + var2 + " AlgorithmParameters implementation in SunJCE provider");
         } catch (NoSuchProviderException var6) {
            throw new RuntimeException("Cannot find SunJCE provider");
         }

         try {
            var1.init(new IvParameterSpec(this.iv));
         } catch (InvalidParameterSpecException var4) {
            throw new RuntimeException("IvParameterSpec not supported");
         }
      }

      return var1;
   }

   protected int engineGetKeySize(Key var1) throws InvalidKeyException {
      byte[] var2 = var1.getEncoded();
      if (var2.length != 24) {
         throw new InvalidKeyException("Invalid key length: " + var2.length + " bytes");
      } else {
         return 112;
      }
   }

   protected byte[] engineWrap(Key var1) throws IllegalBlockSizeException, InvalidKeyException {
      byte[] var2 = var1.getEncoded();
      if (var2 != null && var2.length != 0) {
         byte[] var3 = getChecksum(var2);
         byte[] var4 = new byte[this.iv.length + var2.length + var3.length];
         System.arraycopy(var2, 0, var4, this.iv.length, var2.length);
         System.arraycopy(var3, 0, var4, this.iv.length + var2.length, var3.length);
         this.cipher.encrypt(var4, this.iv.length, var2.length + var3.length, var4, this.iv.length);
         System.arraycopy(this.iv, 0, var4, 0, this.iv.length);

         for(int var5 = 0; var5 < var4.length / 2; ++var5) {
            byte var6 = var4[var5];
            var4[var5] = var4[var4.length - 1 - var5];
            var4[var4.length - 1 - var5] = var6;
         }

         try {
            this.cipher.init(false, this.cipherKey.getAlgorithm(), this.cipherKey.getEncoded(), IV2);
         } catch (InvalidKeyException var8) {
            throw new RuntimeException("Internal cipher key is corrupted");
         }

         this.cipher.encrypt(var4, 0, var4.length, var4, 0);

         try {
            this.cipher.init(this.decrypting, this.cipherKey.getAlgorithm(), this.cipherKey.getEncoded(), this.iv);
            return var4;
         } catch (InvalidKeyException var7) {
            throw new RuntimeException("Internal cipher key is corrupted");
         }
      } else {
         throw new InvalidKeyException("Cannot get an encoding of the key to be wrapped");
      }
   }

   protected Key engineUnwrap(byte[] var1, String var2, int var3) throws InvalidKeyException, NoSuchAlgorithmException {
      if (var1.length == 0) {
         throw new InvalidKeyException("The wrapped key is empty");
      } else {
         byte[] var4 = new byte[var1.length];
         this.cipher.decrypt(var1, 0, var1.length, var4, 0);

         int var5;
         for(var5 = 0; var5 < var4.length / 2; ++var5) {
            byte var6 = var4[var5];
            var4[var5] = var4[var4.length - 1 - var5];
            var4[var4.length - 1 - var5] = var6;
         }

         this.iv = new byte[IV2.length];
         System.arraycopy(var4, 0, this.iv, 0, this.iv.length);
         this.cipher.init(true, this.cipherKey.getAlgorithm(), this.cipherKey.getEncoded(), this.iv);
         this.cipher.decrypt(var4, this.iv.length, var4.length - this.iv.length, var4, this.iv.length);
         var5 = var4.length - this.iv.length - 8;
         byte[] var9 = getChecksum(var4, this.iv.length, var5);
         int var7 = this.iv.length + var5;

         for(int var8 = 0; var8 < var9.length; ++var8) {
            if (var4[var7 + var8] != var9[var8]) {
               throw new InvalidKeyException("Checksum comparison failed");
            }
         }

         this.cipher.init(this.decrypting, this.cipherKey.getAlgorithm(), this.cipherKey.getEncoded(), IV2);
         byte[] var10 = new byte[var5];
         System.arraycopy(var4, this.iv.length, var10, 0, var10.length);
         return ConstructKeys.constructKey(var10, var2, var3);
      }
   }

   private static final byte[] getChecksum(byte[] var0) {
      return getChecksum(var0, 0, var0.length);
   }

   private static final byte[] getChecksum(byte[] var0, int var1, int var2) {
      MessageDigest var3 = null;

      try {
         var3 = MessageDigest.getInstance("SHA1");
      } catch (NoSuchAlgorithmException var5) {
         throw new RuntimeException("SHA1 message digest not available");
      }

      var3.update(var0, var1, var2);
      byte[] var4 = new byte[8];
      System.arraycopy(var3.digest(), 0, var4, 0, var4.length);
      return var4;
   }
}
