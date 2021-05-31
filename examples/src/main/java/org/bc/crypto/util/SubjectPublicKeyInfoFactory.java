package org.bc.crypto.util;

import java.io.IOException;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.DERNull;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.asn1.pkcs.RSAPublicKey;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.asn1.x9.X9ObjectIdentifiers;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.DSAPublicKeyParameters;
import org.bc.crypto.params.RSAKeyParameters;

public class SubjectPublicKeyInfoFactory {
   public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter var0) throws IOException {
      if (var0 instanceof RSAKeyParameters) {
         RSAKeyParameters var2 = (RSAKeyParameters)var0;
         return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), new RSAPublicKey(var2.getModulus(), var2.getExponent()));
      } else if (var0 instanceof DSAPublicKeyParameters) {
         DSAPublicKeyParameters var1 = (DSAPublicKeyParameters)var0;
         return new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa), new ASN1Integer(var1.getY()));
      } else {
         throw new IOException("key parameters not recognised.");
      }
   }
}
