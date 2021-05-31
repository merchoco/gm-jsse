package cn.gmssl.com.sun.crypto.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public final class AESWrapCipher extends CipherSpi {
   private static final byte[] IV = new byte[]{-90, -90, -90, -90, -90, -90, -90, -90};
   private static final int blksize = 16;
   private AESCrypt cipher = new AESCrypt();
   private boolean decrypting = false;

   protected void engineSetMode(String var1) throws NoSuchAlgorithmException {
      if (!var1.equalsIgnoreCase("ECB")) {
         throw new NoSuchAlgorithmException(var1 + " cannot be used");
      }
   }

   protected void engineSetPadding(String var1) throws NoSuchPaddingException {
      if (!var1.equalsIgnoreCase("NoPadding")) {
         throw new NoSuchPaddingException(var1 + " cannot be used");
      }
   }

   protected int engineGetBlockSize() {
      return 16;
   }

   protected int engineGetOutputSize(int var1) {
      boolean var2 = false;
      int var3;
      if (this.decrypting) {
         var3 = var1 - 8;
      } else {
         var3 = var1 + 8;
      }

      return var3 < 0 ? 0 : var3;
   }

   protected byte[] engineGetIV() {
      return null;
   }

   protected void engineInit(int var1, Key var2, SecureRandom var3) throws InvalidKeyException {
      if (var1 == 3) {
         this.decrypting = false;
      } else {
         if (var1 != 4) {
            throw new UnsupportedOperationException("This cipher can only be used for key wrapping and unwrapping");
         }

         this.decrypting = true;
      }

      this.cipher.init(this.decrypting, var2.getAlgorithm(), var2.getEncoded());
   }

   protected void engineInit(int var1, Key var2, AlgorithmParameterSpec var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      if (var3 != null) {
         throw new InvalidAlgorithmParameterException("This cipher does not accept any parameters");
      } else {
         this.engineInit(var1, var2, var4);
      }
   }

   protected void engineInit(int var1, Key var2, AlgorithmParameters var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      if (var3 != null) {
         throw new InvalidAlgorithmParameterException("This cipher does not accept any parameters");
      } else {
         this.engineInit(var1, var2, var4);
      }
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
      return null;
   }

   protected int engineGetKeySize(Key var1) throws InvalidKeyException {
      byte[] var2 = var1.getEncoded();
      if (!AESCrypt.isKeySizeValid(var2.length)) {
         throw new InvalidKeyException("Invalid key length: " + var2.length + " bytes");
      } else {
         return var2.length * 8;
      }
   }

   protected byte[] engineWrap(Key var1) throws IllegalBlockSizeException, InvalidKeyException {
      byte[] var2 = var1.getEncoded();
      if (var2 != null && var2.length != 0) {
         byte[] var3 = new byte[var2.length + 8];
         if (var2.length == 8) {
            System.arraycopy(IV, 0, var3, 0, IV.length);
            System.arraycopy(var2, 0, var3, IV.length, 8);
            this.cipher.encryptBlock(var3, 0, var3, 0);
         } else {
            if (var2.length % 8 != 0) {
               throw new IllegalBlockSizeException("length of the to be wrapped key should be multiples of 8 bytes");
            }

            System.arraycopy(IV, 0, var3, 0, IV.length);
            System.arraycopy(var2, 0, var3, IV.length, var2.length);
            int var4 = var2.length / 8;
            byte[] var5 = new byte[16];

            for(int var6 = 0; var6 < 6; ++var6) {
               for(int var7 = 1; var7 <= var4; ++var7) {
                  int var8 = var7 + var6 * var4;
                  System.arraycopy(var3, 0, var5, 0, IV.length);
                  System.arraycopy(var3, var7 * 8, var5, IV.length, 8);
                  this.cipher.encryptBlock(var5, 0, var5, 0);

                  for(int var9 = 1; var8 != 0; ++var9) {
                     byte var10 = (byte)var8;
                     var5[IV.length - var9] ^= var10;
                     var8 >>>= 8;
                  }

                  System.arraycopy(var5, 0, var3, 0, IV.length);
                  System.arraycopy(var5, 8, var3, 8 * var7, 8);
               }
            }
         }

         return var3;
      } else {
         throw new InvalidKeyException("Cannot get an encoding of the key to be wrapped");
      }
   }

   protected Key engineUnwrap(byte[] var1, String var2, int var3) throws InvalidKeyException, NoSuchAlgorithmException {
      int var4 = var1.length;
      if (var4 == 0) {
         throw new InvalidKeyException("The wrapped key is empty");
      } else if (var4 % 8 != 0) {
         throw new InvalidKeyException("The wrapped key has invalid key length");
      } else {
         byte[] var5 = new byte[var4 - 8];
         byte[] var6 = new byte[16];
         int var7;
         if (var4 == 16) {
            this.cipher.decryptBlock(var1, 0, var6, 0);

            for(var7 = 0; var7 < IV.length; ++var7) {
               if (IV[var7] != var6[var7]) {
                  throw new InvalidKeyException("Integrity check failed");
               }
            }

            System.arraycopy(var6, IV.length, var5, 0, var5.length);
         } else {
            System.arraycopy(var1, 0, var6, 0, IV.length);
            System.arraycopy(var1, IV.length, var5, 0, var5.length);
            var7 = var5.length / 8;

            int var8;
            for(var8 = 5; var8 >= 0; --var8) {
               for(int var9 = var7; var9 > 0; --var9) {
                  int var10 = var9 + var8 * var7;
                  System.arraycopy(var5, 8 * (var9 - 1), var6, IV.length, 8);

                  for(int var11 = 1; var10 != 0; ++var11) {
                     byte var12 = (byte)var10;
                     var6[IV.length - var11] ^= var12;
                     var10 >>>= 8;
                  }

                  this.cipher.decryptBlock(var6, 0, var6, 0);
                  System.arraycopy(var6, IV.length, var5, 8 * (var9 - 1), 8);
               }
            }

            for(var8 = 0; var8 < IV.length; ++var8) {
               if (IV[var8] != var6[var8]) {
                  throw new InvalidKeyException("Integrity check failed");
               }
            }
         }

         return ConstructKeys.constructKey(var5, var2, var3);
      }
   }
}
