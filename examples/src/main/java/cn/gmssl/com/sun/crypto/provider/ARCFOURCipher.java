package cn.gmssl.com.sun.crypto.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public final class ARCFOURCipher extends CipherSpi {
   private final int[] S = new int[256];
   private int is;
   private int js;
   private byte[] lastKey;

   private void init(byte[] var1) {
      int var2;
      for(var2 = 0; var2 < 256; this.S[var2] = var2++) {
         ;
      }

      var2 = 0;
      int var3 = 0;

      for(int var4 = 0; var2 < 256; ++var2) {
         int var5 = this.S[var2];
         var3 = var3 + var5 + var1[var4] & 255;
         this.S[var2] = this.S[var3];
         this.S[var3] = var5;
         ++var4;
         if (var4 == var1.length) {
            var4 = 0;
         }
      }

      this.is = 0;
      this.js = 0;
   }

   private void crypt(byte[] var1, int var2, int var3, byte[] var4, int var5) {
      if (this.is < 0) {
         this.init(this.lastKey);
      }

      while(var3-- > 0) {
         this.is = this.is + 1 & 255;
         int var6 = this.S[this.is];
         this.js = this.js + var6 & 255;
         int var7 = this.S[this.js];
         this.S[this.is] = var7;
         this.S[this.js] = var6;
         var4[var5++] = (byte)(var1[var2++] ^ this.S[var6 + var7 & 255]);
      }

   }

   protected void engineSetMode(String var1) throws NoSuchAlgorithmException {
      if (!var1.equalsIgnoreCase("ECB")) {
         throw new NoSuchAlgorithmException("Unsupported mode " + var1);
      }
   }

   protected void engineSetPadding(String var1) throws NoSuchPaddingException {
      if (!var1.equalsIgnoreCase("NoPadding")) {
         throw new NoSuchPaddingException("Padding must be NoPadding");
      }
   }

   protected int engineGetBlockSize() {
      return 0;
   }

   protected int engineGetOutputSize(int var1) {
      return var1;
   }

   protected byte[] engineGetIV() {
      return null;
   }

   protected AlgorithmParameters engineGetParameters() {
      return null;
   }

   protected void engineInit(int var1, Key var2, SecureRandom var3) throws InvalidKeyException {
      this.init(var1, var2);
   }

   protected void engineInit(int var1, Key var2, AlgorithmParameterSpec var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      if (var3 != null) {
         throw new InvalidAlgorithmParameterException("Parameters not supported");
      } else {
         this.init(var1, var2);
      }
   }

   protected void engineInit(int var1, Key var2, AlgorithmParameters var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      if (var3 != null) {
         throw new InvalidAlgorithmParameterException("Parameters not supported");
      } else {
         this.init(var1, var2);
      }
   }

   private void init(int var1, Key var2) throws InvalidKeyException {
      if (var1 >= 1 && var1 <= 4) {
         this.lastKey = getEncodedKey(var2);
         this.init(this.lastKey);
      } else {
         throw new InvalidKeyException("Unknown opmode: " + var1);
      }
   }

   private static byte[] getEncodedKey(Key var0) throws InvalidKeyException {
      String var1 = var0.getAlgorithm();
      if (!var1.equals("RC4") && !var1.equals("ARCFOUR")) {
         throw new InvalidKeyException("Not an ARCFOUR key: " + var1);
      } else if (!"RAW".equals(var0.getFormat())) {
         throw new InvalidKeyException("Key encoding format must be RAW");
      } else {
         byte[] var2 = var0.getEncoded();
         if (var2.length >= 5 && var2.length <= 128) {
            return var2;
         } else {
            throw new InvalidKeyException("Key length must be between 40 and 1024 bit");
         }
      }
   }

   protected byte[] engineUpdate(byte[] var1, int var2, int var3) {
      byte[] var4 = new byte[var3];
      this.crypt(var1, var2, var3, var4, 0);
      return var4;
   }

   protected int engineUpdate(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException {
      if (var4.length - var5 < var3) {
         throw new ShortBufferException("Output buffer too small");
      } else {
         this.crypt(var1, var2, var3, var4, var5);
         return var3;
      }
   }

   protected byte[] engineDoFinal(byte[] var1, int var2, int var3) {
      byte[] var4 = this.engineUpdate(var1, var2, var3);
      this.is = -1;
      return var4;
   }

   protected int engineDoFinal(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException {
      int var6 = this.engineUpdate(var1, var2, var3, var4, var5);
      this.is = -1;
      return var6;
   }

   protected byte[] engineWrap(Key var1) throws IllegalBlockSizeException, InvalidKeyException {
      byte[] var2 = var1.getEncoded();
      if (var2 != null && var2.length != 0) {
         return this.engineDoFinal(var2, 0, var2.length);
      } else {
         throw new InvalidKeyException("Could not obtain encoded key");
      }
   }

   protected Key engineUnwrap(byte[] var1, String var2, int var3) throws InvalidKeyException, NoSuchAlgorithmException {
      byte[] var4 = this.engineDoFinal(var1, 0, var1.length);
      return ConstructKeys.constructKey(var4, var2, var3);
   }

   protected int engineGetKeySize(Key var1) throws InvalidKeyException {
      byte[] var2 = getEncodedKey(var1);
      return var2.length << 3;
   }
}
