package org.bc.jcajce.provider.asymmetric.ec;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Hashtable;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import org.bc.asn1.DERObjectIdentifier;
import org.bc.asn1.nist.NISTObjectIdentifiers;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.asn1.x9.X9IntegerConverter;
import org.bc.crypto.BasicAgreement;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DerivationFunction;
import org.bc.crypto.agreement.ECDHBasicAgreement;
import org.bc.crypto.agreement.ECDHCBasicAgreement;
import org.bc.crypto.agreement.ECMQVBasicAgreement;
import org.bc.crypto.agreement.kdf.DHKDFParameters;
import org.bc.crypto.agreement.kdf.ECDHKEKGenerator;
import org.bc.crypto.digests.SHA1Digest;
import org.bc.crypto.params.ECDomainParameters;
import org.bc.crypto.params.ECPrivateKeyParameters;
import org.bc.crypto.params.ECPublicKeyParameters;
import org.bc.crypto.params.MQVPrivateParameters;
import org.bc.crypto.params.MQVPublicParameters;
import org.bc.jce.interfaces.ECPrivateKey;
import org.bc.jce.interfaces.ECPublicKey;
import org.bc.jce.interfaces.MQVPrivateKey;
import org.bc.jce.interfaces.MQVPublicKey;
import org.bc.util.Integers;

public class KeyAgreementSpi extends javax.crypto.KeyAgreementSpi {
   private static final X9IntegerConverter converter = new X9IntegerConverter();
   private static final Hashtable algorithms = new Hashtable();
   private String kaAlgorithm;
   private BigInteger result;
   private ECDomainParameters parameters;
   private BasicAgreement agreement;
   private DerivationFunction kdf;

   static {
      Integer var0 = Integers.valueOf(128);
      Integer var1 = Integers.valueOf(192);
      Integer var2 = Integers.valueOf(256);
      algorithms.put(NISTObjectIdentifiers.id_aes128_CBC.getId(), var0);
      algorithms.put(NISTObjectIdentifiers.id_aes192_CBC.getId(), var1);
      algorithms.put(NISTObjectIdentifiers.id_aes256_CBC.getId(), var2);
      algorithms.put(NISTObjectIdentifiers.id_aes128_wrap.getId(), var0);
      algorithms.put(NISTObjectIdentifiers.id_aes192_wrap.getId(), var1);
      algorithms.put(NISTObjectIdentifiers.id_aes256_wrap.getId(), var2);
      algorithms.put(PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId(), var1);
   }

   private byte[] bigIntToBytes(BigInteger var1) {
      return converter.integerToBytes(var1, converter.getByteLength(this.parameters.getG().getX()));
   }

   protected KeyAgreementSpi(String var1, BasicAgreement var2, DerivationFunction var3) {
      this.kaAlgorithm = var1;
      this.agreement = var2;
      this.kdf = var3;
   }

   protected Key engineDoPhase(Key var1, boolean var2) throws InvalidKeyException, IllegalStateException {
      if (this.parameters == null) {
         throw new IllegalStateException(this.kaAlgorithm + " not initialised.");
      } else if (!var2) {
         throw new IllegalStateException(this.kaAlgorithm + " can only be between two parties.");
      } else {
         Object var3;
         if (this.agreement instanceof ECMQVBasicAgreement) {
            if (!(var1 instanceof MQVPublicKey)) {
               throw new InvalidKeyException(this.kaAlgorithm + " key agreement requires " + getSimpleName(MQVPublicKey.class) + " for doPhase");
            }

            MQVPublicKey var4 = (MQVPublicKey)var1;
            ECPublicKeyParameters var5 = (ECPublicKeyParameters)ECUtil.generatePublicKeyParameter(var4.getStaticKey());
            ECPublicKeyParameters var6 = (ECPublicKeyParameters)ECUtil.generatePublicKeyParameter(var4.getEphemeralKey());
            var3 = new MQVPublicParameters(var5, var6);
         } else {
            if (!(var1 instanceof PublicKey)) {
               throw new InvalidKeyException(this.kaAlgorithm + " key agreement requires " + getSimpleName(ECPublicKey.class) + " for doPhase");
            }

            var3 = ECUtil.generatePublicKeyParameter((PublicKey)var1);
         }

         this.result = this.agreement.calculateAgreement((CipherParameters)var3);
         return null;
      }
   }

   protected byte[] engineGenerateSecret() throws IllegalStateException {
      if (this.kdf != null) {
         throw new UnsupportedOperationException("KDF can only be used when algorithm is known");
      } else {
         return this.bigIntToBytes(this.result);
      }
   }

   protected int engineGenerateSecret(byte[] var1, int var2) throws IllegalStateException, ShortBufferException {
      byte[] var3 = this.engineGenerateSecret();
      if (var1.length - var2 < var3.length) {
         throw new ShortBufferException(this.kaAlgorithm + " key agreement: need " + var3.length + " bytes");
      } else {
         System.arraycopy(var3, 0, var1, var2, var3.length);
         return var3.length;
      }
   }

   protected SecretKey engineGenerateSecret(String var1) throws NoSuchAlgorithmException {
      byte[] var2 = this.bigIntToBytes(this.result);
      if (this.kdf != null) {
         if (!algorithms.containsKey(var1)) {
            throw new NoSuchAlgorithmException("unknown algorithm encountered: " + var1);
         }

         int var3 = (Integer)algorithms.get(var1);
         DHKDFParameters var4 = new DHKDFParameters(new DERObjectIdentifier(var1), var3, var2);
         byte[] var5 = new byte[var3 / 8];
         this.kdf.init(var4);
         this.kdf.generateBytes(var5, 0, var5.length);
         var2 = var5;
      }

      return new SecretKeySpec(var2, var1);
   }

   protected void engineInit(Key var1, AlgorithmParameterSpec var2, SecureRandom var3) throws InvalidKeyException, InvalidAlgorithmParameterException {
      this.initFromKey(var1);
   }

   protected void engineInit(Key var1, SecureRandom var2) throws InvalidKeyException {
      this.initFromKey(var1);
   }

   private void initFromKey(Key var1) throws InvalidKeyException {
      if (this.agreement instanceof ECMQVBasicAgreement) {
         if (!(var1 instanceof MQVPrivateKey)) {
            throw new InvalidKeyException(this.kaAlgorithm + " key agreement requires " + getSimpleName(MQVPrivateKey.class) + " for initialisation");
         }

         MQVPrivateKey var2 = (MQVPrivateKey)var1;
         ECPrivateKeyParameters var3 = (ECPrivateKeyParameters)ECUtil.generatePrivateKeyParameter(var2.getStaticPrivateKey());
         ECPrivateKeyParameters var4 = (ECPrivateKeyParameters)ECUtil.generatePrivateKeyParameter(var2.getEphemeralPrivateKey());
         ECPublicKeyParameters var5 = null;
         if (var2.getEphemeralPublicKey() != null) {
            var5 = (ECPublicKeyParameters)ECUtil.generatePublicKeyParameter(var2.getEphemeralPublicKey());
         }

         MQVPrivateParameters var6 = new MQVPrivateParameters(var3, var4, var5);
         this.parameters = var3.getParameters();
         this.agreement.init(var6);
      } else {
         if (!(var1 instanceof PrivateKey)) {
            throw new InvalidKeyException(this.kaAlgorithm + " key agreement requires " + getSimpleName(ECPrivateKey.class) + " for initialisation");
         }

         ECPrivateKeyParameters var7 = (ECPrivateKeyParameters)ECUtil.generatePrivateKeyParameter((PrivateKey)var1);
         this.parameters = var7.getParameters();
         this.agreement.init(var7);
      }

   }

   private static String getSimpleName(Class var0) {
      String var1 = var0.getName();
      return var1.substring(var1.lastIndexOf(46) + 1);
   }

   public static class DH extends KeyAgreementSpi {
      public DH() {
         super("ECDH", new ECDHBasicAgreement(), (DerivationFunction)null);
      }
   }

   public static class DHC extends KeyAgreementSpi {
      public DHC() {
         super("ECDHC", new ECDHCBasicAgreement(), (DerivationFunction)null);
      }
   }

   public static class DHwithSHA1KDF extends KeyAgreementSpi {
      public DHwithSHA1KDF() {
         super("ECDHwithSHA1KDF", new ECDHBasicAgreement(), new ECDHKEKGenerator(new SHA1Digest()));
      }
   }

   public static class MQV extends KeyAgreementSpi {
      public MQV() {
         super("ECMQV", new ECMQVBasicAgreement(), (DerivationFunction)null);
      }
   }

   public static class MQVwithSHA1KDF extends KeyAgreementSpi {
      public MQVwithSHA1KDF() {
         super("ECMQVwithSHA1KDF", new ECMQVBasicAgreement(), new ECDHKEKGenerator(new SHA1Digest()));
      }
   }
}
