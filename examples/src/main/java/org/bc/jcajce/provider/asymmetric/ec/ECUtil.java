package org.bc.jcajce.provider.asymmetric.ec;

import cn.gmssl.crypto.impl.sm2.GBNamedCurves;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bc.asn1.nist.NISTNamedCurves;
import org.bc.asn1.pkcs.PrivateKeyInfo;
import org.bc.asn1.sec.SECNamedCurves;
import org.bc.asn1.teletrust.TeleTrusTNamedCurves;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.asn1.x9.X962NamedCurves;
import org.bc.asn1.x9.X9ECParameters;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.ECDomainParameters;
import org.bc.crypto.params.ECPrivateKeyParameters;
import org.bc.crypto.params.ECPublicKeyParameters;
import org.bc.jce.interfaces.ECPrivateKey;
import org.bc.jce.interfaces.ECPublicKey;
import org.bc.jce.provider.BouncyCastleProvider;
import org.bc.jce.spec.ECParameterSpec;

public class ECUtil {
   static int[] convertMidTerms(int[] var0) {
      int[] var1 = new int[3];
      if (var0.length == 1) {
         var1[0] = var0[0];
      } else {
         if (var0.length != 3) {
            throw new IllegalArgumentException("Only Trinomials and pentanomials supported");
         }

         if (var0[0] < var0[1] && var0[0] < var0[2]) {
            var1[0] = var0[0];
            if (var0[1] < var0[2]) {
               var1[1] = var0[1];
               var1[2] = var0[2];
            } else {
               var1[1] = var0[2];
               var1[2] = var0[1];
            }
         } else if (var0[1] < var0[2]) {
            var1[0] = var0[1];
            if (var0[0] < var0[2]) {
               var1[1] = var0[0];
               var1[2] = var0[2];
            } else {
               var1[1] = var0[2];
               var1[2] = var0[0];
            }
         } else {
            var1[0] = var0[2];
            if (var0[0] < var0[1]) {
               var1[1] = var0[0];
               var1[2] = var0[1];
            } else {
               var1[1] = var0[1];
               var1[2] = var0[0];
            }
         }
      }

      return var1;
   }

   public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey var0) throws InvalidKeyException {
      ECParameterSpec var6;
      if (var0 instanceof ECPublicKey) {
         ECPublicKey var5 = (ECPublicKey)var0;
         var6 = var5.getParameters();
         if (var6 == null) {
            var6 = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
            return new ECPublicKeyParameters(((BCECPublicKey)var5).engineGetQ(), new ECDomainParameters(var6.getCurve(), var6.getG(), var6.getN(), var6.getH(), var6.getSeed()));
         } else {
            return new ECPublicKeyParameters(var5.getQ(), new ECDomainParameters(var6.getCurve(), var6.getG(), var6.getN(), var6.getH(), var6.getSeed()));
         }
      } else if (var0 instanceof java.security.interfaces.ECPublicKey) {
         java.security.interfaces.ECPublicKey var4 = (java.security.interfaces.ECPublicKey)var0;
         var6 = EC5Util.convertSpec(var4.getParams(), false);
         return new ECPublicKeyParameters(EC5Util.convertPoint(var4.getParams(), var4.getW(), false), new ECDomainParameters(var6.getCurve(), var6.getG(), var6.getN(), var6.getH(), var6.getSeed()));
      } else {
         try {
            byte[] var1 = var0.getEncoded();
            if (var1 == null) {
               throw new InvalidKeyException("no encoding for EC public key");
            }

            PublicKey var2 = BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfo.getInstance(var1));
            if (var2 instanceof java.security.interfaces.ECPublicKey) {
               return generatePublicKeyParameter(var2);
            }
         } catch (Exception var3) {
            throw new InvalidKeyException("cannot identify EC public key: " + var3.toString());
         }

         throw new InvalidKeyException("cannot identify EC public key.");
      }
   }

   public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey var0) throws InvalidKeyException {
      ECParameterSpec var6;
      if (var0 instanceof ECPrivateKey) {
         ECPrivateKey var5 = (ECPrivateKey)var0;
         var6 = var5.getParameters();
         if (var6 == null) {
            var6 = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
         }

         return new ECPrivateKeyParameters(var5.getD(), new ECDomainParameters(var6.getCurve(), var6.getG(), var6.getN(), var6.getH(), var6.getSeed()));
      } else if (var0 instanceof java.security.interfaces.ECPrivateKey) {
         java.security.interfaces.ECPrivateKey var4 = (java.security.interfaces.ECPrivateKey)var0;
         var6 = EC5Util.convertSpec(var4.getParams(), false);
         return new ECPrivateKeyParameters(var4.getS(), new ECDomainParameters(var6.getCurve(), var6.getG(), var6.getN(), var6.getH(), var6.getSeed()));
      } else {
         try {
            byte[] var1 = var0.getEncoded();
            if (var1 == null) {
               throw new InvalidKeyException("no encoding for EC private key");
            }

            PrivateKey var2 = BouncyCastleProvider.getPrivateKey(PrivateKeyInfo.getInstance(var1));
            if (var2 instanceof java.security.interfaces.ECPrivateKey) {
               return generatePrivateKeyParameter(var2);
            }
         } catch (Exception var3) {
            throw new InvalidKeyException("cannot identify EC private key: " + var3.toString());
         }

         throw new InvalidKeyException("can't identify EC private key.");
      }
   }

   public static ASN1ObjectIdentifier getNamedCurveOid(String var0) {
      ASN1ObjectIdentifier var1 = X962NamedCurves.getOID(var0);
      if (var1 == null) {
         var1 = SECNamedCurves.getOID(var0);
         if (var1 == null) {
            var1 = NISTNamedCurves.getOID(var0);
         }

         if (var1 == null) {
            var1 = TeleTrusTNamedCurves.getOID(var0);
         }

         if (var1 == null) {
            var1 = ECGOST3410NamedCurves.getOID(var0);
         }

         if (var1 == null) {
            var1 = GBNamedCurves.getOID(var0);
         }
      }

      return var1;
   }

   public static X9ECParameters getNamedCurveByOid(ASN1ObjectIdentifier var0) {
      X9ECParameters var1 = X962NamedCurves.getByOID(var0);
      if (var1 == null) {
         var1 = SECNamedCurves.getByOID(var0);
         if (var1 == null) {
            var1 = NISTNamedCurves.getByOID(var0);
         }

         if (var1 == null) {
            var1 = TeleTrusTNamedCurves.getByOID(var0);
         }

         if (var1 == null) {
            var1 = GBNamedCurves.getByOID(var0);
         }
      }

      return var1;
   }

   public static String getCurveName(ASN1ObjectIdentifier var0) {
      String var1 = X962NamedCurves.getName(var0);
      if (var1 == null) {
         var1 = SECNamedCurves.getName(var0);
         if (var1 == null) {
            var1 = NISTNamedCurves.getName(var0);
         }

         if (var1 == null) {
            var1 = TeleTrusTNamedCurves.getName(var0);
         }

         if (var1 == null) {
            var1 = ECGOST3410NamedCurves.getName(var0);
         }

         if (var1 == null) {
            var1 = GBNamedCurves.getName(var0);
         }
      }

      return var1;
   }
}
