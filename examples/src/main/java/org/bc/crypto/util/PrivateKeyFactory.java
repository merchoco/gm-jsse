package org.bc.crypto.util;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1InputStream;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.nist.NISTNamedCurves;
import org.bc.asn1.oiw.ElGamalParameter;
import org.bc.asn1.oiw.OIWObjectIdentifiers;
import org.bc.asn1.pkcs.DHParameter;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.asn1.pkcs.PrivateKeyInfo;
import org.bc.asn1.pkcs.RSAPrivateKey;
import org.bc.asn1.sec.ECPrivateKey;
import org.bc.asn1.sec.SECNamedCurves;
import org.bc.asn1.teletrust.TeleTrusTNamedCurves;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.DSAParameter;
import org.bc.asn1.x9.X962NamedCurves;
import org.bc.asn1.x9.X962Parameters;
import org.bc.asn1.x9.X9ECParameters;
import org.bc.asn1.x9.X9ObjectIdentifiers;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.DHParameters;
import org.bc.crypto.params.DHPrivateKeyParameters;
import org.bc.crypto.params.DSAParameters;
import org.bc.crypto.params.DSAPrivateKeyParameters;
import org.bc.crypto.params.ECDomainParameters;
import org.bc.crypto.params.ECPrivateKeyParameters;
import org.bc.crypto.params.ElGamalParameters;
import org.bc.crypto.params.ElGamalPrivateKeyParameters;
import org.bc.crypto.params.RSAPrivateCrtKeyParameters;

public class PrivateKeyFactory {
   public static AsymmetricKeyParameter createKey(byte[] var0) throws IOException {
      return createKey(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(var0)));
   }

   public static AsymmetricKeyParameter createKey(InputStream var0) throws IOException {
      return createKey(PrivateKeyInfo.getInstance((new ASN1InputStream(var0)).readObject()));
   }

   public static AsymmetricKeyParameter createKey(PrivateKeyInfo var0) throws IOException {
      AlgorithmIdentifier var1 = var0.getPrivateKeyAlgorithm();
      if (var1.getAlgorithm().equals(PKCSObjectIdentifiers.rsaEncryption)) {
         RSAPrivateKey var10 = RSAPrivateKey.getInstance(var0.parsePrivateKey());
         return new RSAPrivateCrtKeyParameters(var10.getModulus(), var10.getPublicExponent(), var10.getPrivateExponent(), var10.getPrime1(), var10.getPrime2(), var10.getExponent1(), var10.getExponent2(), var10.getCoefficient());
      } else {
         ASN1Integer var14;
         if (var1.getAlgorithm().equals(PKCSObjectIdentifiers.dhKeyAgreement)) {
            DHParameter var9 = DHParameter.getInstance(var1.getParameters());
            var14 = (ASN1Integer)var0.parsePrivateKey();
            BigInteger var16 = var9.getL();
            int var17 = var16 == null ? 0 : var16.intValue();
            DHParameters var18 = new DHParameters(var9.getP(), var9.getG(), (BigInteger)null, var17);
            return new DHPrivateKeyParameters(var14.getValue(), var18);
         } else if (var1.getAlgorithm().equals(OIWObjectIdentifiers.elGamalAlgorithm)) {
            ElGamalParameter var8 = new ElGamalParameter((ASN1Sequence)var1.getParameters());
            var14 = (ASN1Integer)var0.parsePrivateKey();
            return new ElGamalPrivateKeyParameters(var14.getValue(), new ElGamalParameters(var8.getP(), var8.getG()));
         } else if (var1.getAlgorithm().equals(X9ObjectIdentifiers.id_dsa)) {
            ASN1Integer var7 = (ASN1Integer)var0.parsePrivateKey();
            ASN1Encodable var13 = var1.getParameters();
            DSAParameters var12 = null;
            if (var13 != null) {
               DSAParameter var15 = DSAParameter.getInstance(var13.toASN1Primitive());
               var12 = new DSAParameters(var15.getP(), var15.getQ(), var15.getG());
            }

            return new DSAPrivateKeyParameters(var7.getValue(), var12);
         } else if (var1.getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey)) {
            X962Parameters var2 = new X962Parameters((ASN1Primitive)var1.getParameters());
            X9ECParameters var3;
            if (var2.isNamedCurve()) {
               ASN1ObjectIdentifier var4 = ASN1ObjectIdentifier.getInstance(var2.getParameters());
               var3 = X962NamedCurves.getByOID(var4);
               if (var3 == null) {
                  var3 = SECNamedCurves.getByOID(var4);
                  if (var3 == null) {
                     var3 = NISTNamedCurves.getByOID(var4);
                     if (var3 == null) {
                        var3 = TeleTrusTNamedCurves.getByOID(var4);
                     }
                  }
               }
            } else {
               var3 = X9ECParameters.getInstance(var2.getParameters());
            }

            ECPrivateKey var11 = ECPrivateKey.getInstance(var0.parsePrivateKey());
            BigInteger var5 = var11.getKey();
            ECDomainParameters var6 = new ECDomainParameters(var3.getCurve(), var3.getG(), var3.getN(), var3.getH(), var3.getSeed());
            return new ECPrivateKeyParameters(var5, var6);
         } else {
            throw new RuntimeException("algorithm identifier in key not recognised");
         }
      }
   }
}
