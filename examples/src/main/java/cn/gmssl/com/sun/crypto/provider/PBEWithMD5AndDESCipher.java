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

public final class PBEWithMD5AndDESCipher extends CipherSpi {
   private PBECipherCore core = new PBECipherCore("DES");

   public PBEWithMD5AndDESCipher() throws NoSuchAlgorithmException, NoSuchPaddingException {
   }

   protected void engineSetMode(String var1) throws NoSuchAlgorithmException {
      if (var1 != null && !var1.equalsIgnoreCase("CBC")) {
         throw new NoSuchAlgorithmException("Invalid cipher mode: " + var1);
      }
   }

   protected void engineSetPadding(String var1) throws NoSuchPaddingException {
      if (var1 != null && !var1.equalsIgnoreCase("PKCS5Padding")) {
         throw new NoSuchPaddingException("Invalid padding scheme: " + var1);
      }
   }

   protected int engineGetBlockSize() {
      return this.core.getBlockSize();
   }

   protected int engineGetOutputSize(int var1) {
      return this.core.getOutputSize(var1);
   }

   protected byte[] engineGetIV() {
      return this.core.getIV();
   }

   protected AlgorithmParameters engineGetParameters() {
      return this.core.getParameters();
   }

   protected void engineInit(int var1, Key var2, SecureRandom var3) throws InvalidKeyException {
      try {
         this.engineInit(var1, var2, (AlgorithmParameterSpec)null, var3);
      } catch (InvalidAlgorithmParameterException var6) {
         InvalidKeyException var5 = new InvalidKeyException("requires PBE parameters");
         var5.initCause(var6);
         throw var5;
      }
   }

   protected void engineInit(int var1, Key var2, AlgorithmParameterSpec var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      this.core.init(var1, var2, var3, var4);
   }

   protected void engineInit(int var1, Key var2, AlgorithmParameters var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      this.core.init(var1, var2, var3, var4);
   }

   protected byte[] engineUpdate(byte[] var1, int var2, int var3) {
      return this.core.update(var1, var2, var3);
   }

   protected int engineUpdate(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException {
      return this.core.update(var1, var2, var3, var4, var5);
   }

   protected byte[] engineDoFinal(byte[] var1, int var2, int var3) throws IllegalBlockSizeException, BadPaddingException {
      return this.core.doFinal(var1, var2, var3);
   }

   protected int engineDoFinal(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
      return this.core.doFinal(var1, var2, var3, var4, var5);
   }

   protected int engineGetKeySize(Key var1) throws InvalidKeyException {
      return 56;
   }

   protected byte[] engineWrap(Key var1) throws IllegalBlockSizeException, InvalidKeyException {
      return this.core.wrap(var1);
   }

   protected Key engineUnwrap(byte[] var1, String var2, int var3) throws InvalidKeyException, NoSuchAlgorithmException {
      return this.core.unwrap(var1, var2, var3);
   }
}
