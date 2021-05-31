package cn.gmssl.security.ec;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

public final class ECDHKeyAgreement extends KeyAgreementSpi {
   private ECPrivateKey privateKey;
   private byte[] publicValue;
   private int secretLen;

   protected void engineInit(Key var1, SecureRandom var2) throws InvalidKeyException {
      if (!(var1 instanceof PrivateKey)) {
         throw new InvalidKeyException("Key must be instance of PrivateKey");
      } else {
         this.privateKey = (ECPrivateKey)ECKeyFactory.toECKey(var1);
         this.publicValue = null;
      }
   }

   protected void engineInit(Key var1, AlgorithmParameterSpec var2, SecureRandom var3) throws InvalidKeyException, InvalidAlgorithmParameterException {
      if (var2 != null) {
         throw new InvalidAlgorithmParameterException("Parameters not supported");
      } else {
         this.engineInit(var1, var3);
      }
   }

   protected Key engineDoPhase(Key var1, boolean var2) throws InvalidKeyException, IllegalStateException {
      if (this.privateKey == null) {
         throw new IllegalStateException("Not initialized");
      } else if (this.publicValue != null) {
         throw new IllegalStateException("Phase already executed");
      } else if (!var2) {
         throw new IllegalStateException("Only two party agreement supported, lastPhase must be true");
      } else if (!(var1 instanceof ECPublicKey)) {
         throw new InvalidKeyException("Key must be a PublicKey with algorithm EC");
      } else {
         ECPublicKey var3 = (ECPublicKey)var1;
         ECParameterSpec var4 = var3.getParams();
         if (var3 instanceof ECPublicKeyImpl) {
            this.publicValue = ((ECPublicKeyImpl)var3).getEncodedPublicValue();
         } else {
            this.publicValue = ECParameters.encodePoint(var3.getW(), var4.getCurve());
         }

         int var5 = var4.getCurve().getField().getFieldSize();
         this.secretLen = var5 + 7 >> 3;
         return null;
      }
   }

   protected byte[] engineGenerateSecret() throws IllegalStateException {
      if (this.privateKey != null && this.publicValue != null) {
         byte[] var1 = this.privateKey.getS().toByteArray();
         byte[] var2 = ECParameters.encodeParameters(this.privateKey.getParams());

         try {
            return deriveKey(var1, this.publicValue, var2);
         } catch (GeneralSecurityException var4) {
            throw new ProviderException("Could not derive key", var4);
         }
      } else {
         throw new IllegalStateException("Not initialized correctly");
      }
   }

   protected int engineGenerateSecret(byte[] var1, int var2) throws IllegalStateException, ShortBufferException {
      if (var2 + this.secretLen > var1.length) {
         throw new ShortBufferException("Need " + this.secretLen + " bytes, only " + (var1.length - var2) + " available");
      } else {
         byte[] var3 = this.engineGenerateSecret();
         System.arraycopy(var3, 0, var1, var2, var3.length);
         return var3.length;
      }
   }

   protected SecretKey engineGenerateSecret(String var1) throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
      if (var1 == null) {
         throw new NoSuchAlgorithmException("Algorithm must not be null");
      } else if (!var1.equals("TlsPremasterSecret")) {
         throw new NoSuchAlgorithmException("Only supported for algorithm TlsPremasterSecret");
      } else {
         return new SecretKeySpec(this.engineGenerateSecret(), "TlsPremasterSecret");
      }
   }

   private static native byte[] deriveKey(byte[] var0, byte[] var1, byte[] var2) throws GeneralSecurityException;
}
