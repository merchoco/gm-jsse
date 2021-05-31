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
import org.bc.asn1.DEROctetString;
import org.bc.asn1.nist.NISTNamedCurves;
import org.bc.asn1.oiw.ElGamalParameter;
import org.bc.asn1.oiw.OIWObjectIdentifiers;
import org.bc.asn1.pkcs.DHParameter;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.asn1.pkcs.RSAPublicKey;
import org.bc.asn1.sec.SECNamedCurves;
import org.bc.asn1.teletrust.TeleTrusTNamedCurves;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.DSAParameter;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.asn1.x509.X509ObjectIdentifiers;
import org.bc.asn1.x9.DHDomainParameters;
import org.bc.asn1.x9.DHPublicKey;
import org.bc.asn1.x9.DHValidationParms;
import org.bc.asn1.x9.X962NamedCurves;
import org.bc.asn1.x9.X962Parameters;
import org.bc.asn1.x9.X9ECParameters;
import org.bc.asn1.x9.X9ECPoint;
import org.bc.asn1.x9.X9ObjectIdentifiers;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.DHParameters;
import org.bc.crypto.params.DHPublicKeyParameters;
import org.bc.crypto.params.DHValidationParameters;
import org.bc.crypto.params.DSAParameters;
import org.bc.crypto.params.DSAPublicKeyParameters;
import org.bc.crypto.params.ECDomainParameters;
import org.bc.crypto.params.ECPublicKeyParameters;
import org.bc.crypto.params.ElGamalParameters;
import org.bc.crypto.params.ElGamalPublicKeyParameters;
import org.bc.crypto.params.RSAKeyParameters;

public class PublicKeyFactory {
   public static AsymmetricKeyParameter createKey(byte[] var0) throws IOException {
      return createKey(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(var0)));
   }

   public static AsymmetricKeyParameter createKey(InputStream var0) throws IOException {
      return createKey(SubjectPublicKeyInfo.getInstance((new ASN1InputStream(var0)).readObject()));
   }

   public static AsymmetricKeyParameter createKey(SubjectPublicKeyInfo var0) throws IOException {
      AlgorithmIdentifier var1 = var0.getAlgorithm();
      if (!var1.getAlgorithm().equals(PKCSObjectIdentifiers.rsaEncryption) && !var1.getAlgorithm().equals(X509ObjectIdentifiers.id_ea_rsa)) {
         if (var1.getAlgorithm().equals(X9ObjectIdentifiers.dhpublicnumber)) {
            DHPublicKey var18 = DHPublicKey.getInstance(var0.parsePublicKey());
            BigInteger var25 = var18.getY().getValue();
            DHDomainParameters var26 = DHDomainParameters.getInstance(var1.getParameters());
            BigInteger var27 = var26.getP().getValue();
            BigInteger var29 = var26.getG().getValue();
            BigInteger var7 = var26.getQ().getValue();
            BigInteger var8 = null;
            if (var26.getJ() != null) {
               var8 = var26.getJ().getValue();
            }

            DHValidationParameters var9 = null;
            DHValidationParms var10 = var26.getValidationParms();
            if (var10 != null) {
               byte[] var11 = var10.getSeed().getBytes();
               BigInteger var12 = var10.getPgenCounter().getValue();
               var9 = new DHValidationParameters(var11, var12.intValue());
            }

            return new DHPublicKeyParameters(var25, new DHParameters(var27, var29, var7, var8, var9));
         } else {
            ASN1Integer var20;
            if (var1.getAlgorithm().equals(PKCSObjectIdentifiers.dhKeyAgreement)) {
               DHParameter var16 = DHParameter.getInstance(var1.getParameters());
               var20 = (ASN1Integer)var0.parsePublicKey();
               BigInteger var23 = var16.getL();
               int var24 = var23 == null ? 0 : var23.intValue();
               DHParameters var28 = new DHParameters(var16.getP(), var16.getG(), (BigInteger)null, var24);
               return new DHPublicKeyParameters(var20.getValue(), var28);
            } else if (var1.getAlgorithm().equals(OIWObjectIdentifiers.elGamalAlgorithm)) {
               ElGamalParameter var15 = new ElGamalParameter((ASN1Sequence)var1.getParameters());
               var20 = (ASN1Integer)var0.parsePublicKey();
               return new ElGamalPublicKeyParameters(var20.getValue(), new ElGamalParameters(var15.getP(), var15.getG()));
            } else if (!var1.getAlgorithm().equals(X9ObjectIdentifiers.id_dsa) && !var1.getAlgorithm().equals(OIWObjectIdentifiers.dsaWithSHA1)) {
               if (var1.getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey)) {
                  X962Parameters var14 = new X962Parameters((ASN1Primitive)var1.getParameters());
                  X9ECParameters var17;
                  if (var14.isNamedCurve()) {
                     ASN1ObjectIdentifier var19 = (ASN1ObjectIdentifier)var14.getParameters();
                     var17 = X962NamedCurves.getByOID(var19);
                     if (var17 == null) {
                        var17 = SECNamedCurves.getByOID(var19);
                        if (var17 == null) {
                           var17 = NISTNamedCurves.getByOID(var19);
                           if (var17 == null) {
                              var17 = TeleTrusTNamedCurves.getByOID(var19);
                           }
                        }
                     }
                  } else {
                     var17 = X9ECParameters.getInstance(var14.getParameters());
                  }

                  DEROctetString var21 = new DEROctetString(var0.getPublicKeyData().getBytes());
                  X9ECPoint var22 = new X9ECPoint(var17.getCurve(), var21);
                  ECDomainParameters var6 = new ECDomainParameters(var17.getCurve(), var17.getG(), var17.getN(), var17.getH(), var17.getSeed());
                  return new ECPublicKeyParameters(var22.getPoint(), var6);
               } else {
                  throw new RuntimeException("algorithm identifier in key not recognised");
               }
            } else {
               ASN1Integer var13 = (ASN1Integer)var0.parsePublicKey();
               ASN1Encodable var3 = var1.getParameters();
               DSAParameters var4 = null;
               if (var3 != null) {
                  DSAParameter var5 = DSAParameter.getInstance(var3.toASN1Primitive());
                  var4 = new DSAParameters(var5.getP(), var5.getQ(), var5.getG());
               }

               return new DSAPublicKeyParameters(var13.getValue(), var4);
            }
         }
      } else {
         RSAPublicKey var2 = RSAPublicKey.getInstance(var0.parsePublicKey());
         return new RSAKeyParameters(false, var2.getModulus(), var2.getPublicExponent());
      }
   }
}
