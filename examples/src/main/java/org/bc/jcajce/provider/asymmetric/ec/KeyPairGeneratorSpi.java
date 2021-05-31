package org.bc.jcajce.provider.asymmetric.ec;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Hashtable;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.nist.NISTNamedCurves;
import org.bc.asn1.sec.SECNamedCurves;
import org.bc.asn1.teletrust.TeleTrusTNamedCurves;
import org.bc.asn1.x9.X962NamedCurves;
import org.bc.asn1.x9.X9ECParameters;
import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.generators.ECKeyPairGenerator;
import org.bc.crypto.params.ECDomainParameters;
import org.bc.crypto.params.ECKeyGenerationParameters;
import org.bc.crypto.params.ECPrivateKeyParameters;
import org.bc.crypto.params.ECPublicKeyParameters;
import org.bc.jcajce.provider.config.ProviderConfiguration;
import org.bc.jce.provider.BouncyCastleProvider;
import org.bc.jce.spec.ECNamedCurveGenParameterSpec;
import org.bc.jce.spec.ECNamedCurveSpec;
import org.bc.jce.spec.ECParameterSpec;
import org.bc.math.ec.ECCurve;
import org.bc.math.ec.ECPoint;
import org.bc.util.Integers;

public abstract class KeyPairGeneratorSpi extends KeyPairGenerator {
   public KeyPairGeneratorSpi(String var1) {
      super(var1);
   }

   public static class EC extends KeyPairGeneratorSpi {
      ECKeyGenerationParameters param;
      ECKeyPairGenerator engine = new ECKeyPairGenerator();
      Object ecParams = null;
      int strength = 239;
      int certainty = 50;
      SecureRandom random = new SecureRandom();
      boolean initialised = false;
      String algorithm;
      ProviderConfiguration configuration;
      private static Hashtable ecParameters = new Hashtable();

      static {
         ecParameters.put(Integers.valueOf(192), new ECGenParameterSpec("prime192v1"));
         ecParameters.put(Integers.valueOf(239), new ECGenParameterSpec("prime239v1"));
         ecParameters.put(Integers.valueOf(256), new ECGenParameterSpec("prime256v1"));
         ecParameters.put(Integers.valueOf(224), new ECGenParameterSpec("P-224"));
         ecParameters.put(Integers.valueOf(384), new ECGenParameterSpec("P-384"));
         ecParameters.put(Integers.valueOf(521), new ECGenParameterSpec("P-521"));
      }

      public EC() {
         super("EC");
         this.algorithm = "EC";
         this.configuration = BouncyCastleProvider.CONFIGURATION;
      }

      public EC(String var1, ProviderConfiguration var2) {
         super(var1);
         this.algorithm = var1;
         this.configuration = var2;
      }

      public void initialize(int var1, SecureRandom var2) {
         this.strength = var1;
         this.random = var2;
         ECGenParameterSpec var3 = (ECGenParameterSpec)ecParameters.get(Integers.valueOf(var1));
         if (var3 != null) {
            try {
               this.initialize(var3, var2);
            } catch (InvalidAlgorithmParameterException var5) {
               throw new InvalidParameterException("key size not configurable.");
            }
         } else {
            throw new InvalidParameterException("unknown key size.");
         }
      }

      public void initialize(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
         ECParameterSpec var9;
         if (var1 instanceof ECParameterSpec) {
            var9 = (ECParameterSpec)var1;
            this.ecParams = var1;
            this.param = new ECKeyGenerationParameters(new ECDomainParameters(var9.getCurve(), var9.getG(), var9.getN()), var2);
            this.engine.init(this.param);
            this.initialised = true;
         } else if (var1 instanceof java.security.spec.ECParameterSpec) {
            java.security.spec.ECParameterSpec var10 = (java.security.spec.ECParameterSpec)var1;
            this.ecParams = var1;
            ECCurve var13 = EC5Util.convertCurve(var10.getCurve());
            ECPoint var12 = EC5Util.convertPoint(var13, var10.getGenerator(), false);
            this.param = new ECKeyGenerationParameters(new ECDomainParameters(var13, var12, var10.getOrder(), BigInteger.valueOf((long)var10.getCofactor())), var2);
            this.engine.init(this.param);
            this.initialised = true;
         } else if (!(var1 instanceof ECGenParameterSpec) && !(var1 instanceof ECNamedCurveGenParameterSpec)) {
            if (var1 != null || this.configuration.getEcImplicitlyCa() == null) {
               if (var1 == null && this.configuration.getEcImplicitlyCa() == null) {
                  throw new InvalidAlgorithmParameterException("null parameter passed but no implicitCA set");
               }

               throw new InvalidAlgorithmParameterException("parameter object not a ECParameterSpec");
            }

            var9 = this.configuration.getEcImplicitlyCa();
            this.ecParams = var1;
            this.param = new ECKeyGenerationParameters(new ECDomainParameters(var9.getCurve(), var9.getG(), var9.getN()), var2);
            this.engine.init(this.param);
            this.initialised = true;
         } else {
            String var3;
            if (var1 instanceof ECGenParameterSpec) {
               var3 = ((ECGenParameterSpec)var1).getName();
            } else {
               var3 = ((ECNamedCurveGenParameterSpec)var1).getName();
            }

            X9ECParameters var4 = X962NamedCurves.getByName(var3);
            if (var4 == null) {
               var4 = SECNamedCurves.getByName(var3);
               if (var4 == null) {
                  var4 = NISTNamedCurves.getByName(var3);
               }

               if (var4 == null) {
                  var4 = TeleTrusTNamedCurves.getByName(var3);
               }

               if (var4 == null) {
                  try {
                     ASN1ObjectIdentifier var5 = new ASN1ObjectIdentifier(var3);
                     var4 = X962NamedCurves.getByOID(var5);
                     if (var4 == null) {
                        var4 = SECNamedCurves.getByOID(var5);
                     }

                     if (var4 == null) {
                        var4 = NISTNamedCurves.getByOID(var5);
                     }

                     if (var4 == null) {
                        var4 = TeleTrusTNamedCurves.getByOID(var5);
                     }

                     if (var4 == null) {
                        throw new InvalidAlgorithmParameterException("unknown curve OID: " + var3);
                     }
                  } catch (IllegalArgumentException var8) {
                     throw new InvalidAlgorithmParameterException("unknown curve name: " + var3);
                  }
               }
            }

            this.ecParams = new ECNamedCurveSpec(var3, var4.getCurve(), var4.getG(), var4.getN(), var4.getH(), (byte[])null);
            java.security.spec.ECParameterSpec var11 = (java.security.spec.ECParameterSpec)this.ecParams;
            ECCurve var6 = EC5Util.convertCurve(var11.getCurve());
            ECPoint var7 = EC5Util.convertPoint(var6, var11.getGenerator(), false);
            this.param = new ECKeyGenerationParameters(new ECDomainParameters(var6, var7, var11.getOrder(), BigInteger.valueOf((long)var11.getCofactor())), var2);
            this.engine.init(this.param);
            this.initialised = true;
         }

      }

      public KeyPair generateKeyPair() {
         if (!this.initialised) {
            this.initialize(this.strength, new SecureRandom());
         }

         AsymmetricCipherKeyPair var1 = this.engine.generateKeyPair();
         ECPublicKeyParameters var2 = (ECPublicKeyParameters)var1.getPublic();
         ECPrivateKeyParameters var3 = (ECPrivateKeyParameters)var1.getPrivate();
         BCECPublicKey var5;
         if (this.ecParams instanceof ECParameterSpec) {
            ECParameterSpec var6 = (ECParameterSpec)this.ecParams;
            var5 = new BCECPublicKey(this.algorithm, var2, var6, this.configuration);
            return new KeyPair(var5, new BCECPrivateKey(this.algorithm, var3, var5, var6, this.configuration));
         } else if (this.ecParams == null) {
            return new KeyPair(new BCECPublicKey(this.algorithm, var2, this.configuration), new BCECPrivateKey(this.algorithm, var3, this.configuration));
         } else {
            java.security.spec.ECParameterSpec var4 = (java.security.spec.ECParameterSpec)this.ecParams;
            var5 = new BCECPublicKey(this.algorithm, var2, var4, this.configuration);
            return new KeyPair(var5, new BCECPrivateKey(this.algorithm, var3, var5, var4, this.configuration));
         }
      }
   }

   public static class ECDH extends KeyPairGeneratorSpi.EC {
      public ECDH() {
         super("ECDH", BouncyCastleProvider.CONFIGURATION);
      }
   }

   public static class ECDHC extends KeyPairGeneratorSpi.EC {
      public ECDHC() {
         super("ECDHC", BouncyCastleProvider.CONFIGURATION);
      }
   }

   public static class ECDSA extends KeyPairGeneratorSpi.EC {
      public ECDSA() {
         super("ECDSA", BouncyCastleProvider.CONFIGURATION);
      }
   }

   public static class ECMQV extends KeyPairGeneratorSpi.EC {
      public ECMQV() {
         super("ECMQV", BouncyCastleProvider.CONFIGURATION);
      }
   }
}
