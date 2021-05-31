package cn.gmssl.crypto;

import cn.gmssl.crypto.impl.sm2.SM2Encryption;
import cn.gmssl.jce.skf.SKF_PrivateKey;
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
import javax.crypto.spec.SecretKeySpec;
import org.bc.jce.interfaces.ECPrivateKey;
import org.bc.jce.interfaces.ECPublicKey;

public class SM2DerJce extends CipherSpi {
   private boolean skf = false;
   private SKF_PrivateKey skfPri = null;
   private int opmode = -1;
   private Key key = null;
   private SecureRandom random = null;

   protected void engineSetMode(String var1) throws NoSuchAlgorithmException {
      throw new UnsupportedOperationException("engineSetMode");
   }

   protected void engineSetPadding(String var1) throws NoSuchPaddingException {
      throw new UnsupportedOperationException("engineSetPadding");
   }

   protected int engineGetBlockSize() {
      throw new UnsupportedOperationException("engineGetBlockSize");
   }

   protected int engineGetOutputSize(int var1) {
      throw new UnsupportedOperationException("engineGetOutputSize");
   }

   protected byte[] engineGetIV() {
      throw new UnsupportedOperationException("engineGetIV");
   }

   protected AlgorithmParameters engineGetParameters() {
      throw new UnsupportedOperationException("engineGetParameters");
   }

   protected int engineGetKeySize(Key var1) throws InvalidKeyException {
      return super.engineGetKeySize(var1);
   }

   protected void engineInit(int var1, Key var2, SecureRandom var3) throws InvalidKeyException {
      try {
         this.engineInit(var1, var2, (AlgorithmParameterSpec)null, var3);
      } catch (Exception var5) {
         throw new InvalidKeyException(var5);
      }
   }

   protected void engineInit(int var1, Key var2, AlgorithmParameterSpec var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      if (var1 == 1 && !(var2 instanceof ECPublicKey)) {
         throw new InvalidKeyException("sm2 encryption can only public only");
      } else if (var1 == 2 && !(var2 instanceof ECPrivateKey)) {
         throw new InvalidKeyException("sm2 decryption can use ec private only");
      } else {
         this.opmode = var1;
         this.key = var2;
         this.random = var4;
      }
   }

   protected void engineInit(int var1, Key var2, AlgorithmParameters var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      throw new UnsupportedOperationException();
   }

   protected byte[] engineUpdate(byte[] var1, int var2, int var3) {
      throw new UnsupportedOperationException("engineUpdate");
   }

   protected int engineUpdate(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException {
      throw new UnsupportedOperationException("engineUpdate");
   }

   protected byte[] engineDoFinal(byte[] var1, int var2, int var3) throws IllegalBlockSizeException, BadPaddingException {
      Object var4 = null;
      byte[] var5 = new byte[var3];
      System.arraycopy(var1, var2, var5, 0, var3);

      try {
         byte[] var8;
         if (this.opmode == 1) {
            ECPublicKey var6 = (ECPublicKey)this.key;
            var8 = SM2Encryption.encrypt_der(var6, var5, this.random);
         } else {
            if (this.opmode != 2) {
               throw new RuntimeException("unsupported mode in sm2 : " + this.opmode);
            }

            ECPrivateKey var9 = (ECPrivateKey)this.key;
            var8 = SM2Encryption.decrypt_der(var9, var5);
         }

         return var8;
      } catch (Exception var7) {
         throw new RuntimeException(var7);
      }
   }

   protected int engineDoFinal(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
      return 0;
   }

   protected byte[] engineWrap(Key var1) throws IllegalBlockSizeException, InvalidKeyException {
      ECPublicKey var2 = (ECPublicKey)this.key;

      try {
         return SM2Encryption.encrypt_der(var2, var1.getEncoded(), this.random);
      } catch (Exception var4) {
         throw new RuntimeException(var4);
      }
   }

   protected Key engineUnwrap(byte[] var1, String var2, int var3) throws InvalidKeyException, NoSuchAlgorithmException {
      ECPrivateKey var4 = (ECPrivateKey)this.key;

      byte[] var5;
      try {
         var5 = SM2Encryption.decrypt_der(var4, var1);
      } catch (Exception var7) {
         throw new RuntimeException(var7);
      }

      return new SecretKeySpec(var5, "TlsEccPremasterSecret");
   }
}
