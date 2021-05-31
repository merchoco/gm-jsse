package cn.gmssl.security.ec;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import sun.security.jca.JCAUtil;

public final class ECKeyPairGenerator extends KeyPairGeneratorSpi {
   private static final int KEY_SIZE_MIN = 112;
   private static final int KEY_SIZE_MAX = 571;
   private static final int KEY_SIZE_DEFAULT = 256;
   private SecureRandom random;
   private int keySize;
   private AlgorithmParameterSpec params = null;

   public ECKeyPairGenerator() {
      this.initialize(256, (SecureRandom)null);
   }

   public void initialize(int var1, SecureRandom var2) {
      this.checkKeySize(var1);
      this.params = NamedCurve.getECParameterSpec(var1);
      if (this.params == null) {
         throw new InvalidParameterException("No EC parameters available for key size " + var1 + " bits");
      } else {
         this.random = var2;
      }
   }

   public void initialize(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      if (var1 instanceof ECParameterSpec) {
         this.params = ECParameters.getNamedCurve((ECParameterSpec)var1);
         if (this.params == null) {
            throw new InvalidAlgorithmParameterException("Unsupported curve: " + var1);
         }
      } else {
         if (!(var1 instanceof ECGenParameterSpec)) {
            throw new InvalidAlgorithmParameterException("ECParameterSpec or ECGenParameterSpec required for EC");
         }

         String var3 = ((ECGenParameterSpec)var1).getName();
         this.params = NamedCurve.getECParameterSpec(var3);
         if (this.params == null) {
            throw new InvalidAlgorithmParameterException("Unknown curve name: " + var3);
         }
      }

      this.keySize = ((ECParameterSpec)this.params).getCurve().getField().getFieldSize();
      this.random = var2;
   }

   public KeyPair generateKeyPair() {
      byte[] var1 = ECParameters.encodeParameters((ECParameterSpec)this.params);
      byte[] var2 = new byte[((this.keySize + 7 >> 3) + 1) * 2];
      if (this.random == null) {
         this.random = JCAUtil.getSecureRandom();
      }

      this.random.nextBytes(var2);

      try {
         long[] var3 = generateECKeyPair(this.keySize, var1, var2);
         BigInteger var4 = new BigInteger(1, getEncodedBytes(var3[0]));
         ECPrivateKeyImpl var5 = new ECPrivateKeyImpl(var4, (ECParameterSpec)this.params);
         ECPoint var6 = ECParameters.decodePoint(getEncodedBytes(var3[1]), ((ECParameterSpec)this.params).getCurve());
         ECPublicKeyImpl var7 = new ECPublicKeyImpl(var6, (ECParameterSpec)this.params);
         return new KeyPair(var7, var5);
      } catch (Exception var8) {
         throw new ProviderException(var8);
      }
   }

   private void checkKeySize(int var1) throws InvalidParameterException {
      if (var1 < 112) {
         throw new InvalidParameterException("Key size must be at least 112 bits");
      } else if (var1 > 571) {
         throw new InvalidParameterException("Key size must be at most 571 bits");
      } else {
         this.keySize = var1;
      }
   }

   private static native long[] generateECKeyPair(int var0, byte[] var1, byte[] var2) throws GeneralSecurityException;

   private static native byte[] getEncodedBytes(long var0);
}
