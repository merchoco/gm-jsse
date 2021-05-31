package org.bc.crypto.util;

import java.io.IOException;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.DERNull;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.asn1.pkcs.PrivateKeyInfo;
import org.bc.asn1.pkcs.RSAPrivateKey;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.DSAParameter;
import org.bc.asn1.x9.X9ObjectIdentifiers;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.DSAParameters;
import org.bc.crypto.params.DSAPrivateKeyParameters;
import org.bc.crypto.params.RSAKeyParameters;
import org.bc.crypto.params.RSAPrivateCrtKeyParameters;

public class PrivateKeyInfoFactory {
   public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter var0) throws IOException {
      if (var0 instanceof RSAKeyParameters) {
         RSAPrivateCrtKeyParameters var3 = (RSAPrivateCrtKeyParameters)var0;
         return new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), new RSAPrivateKey(var3.getModulus(), var3.getPublicExponent(), var3.getExponent(), var3.getP(), var3.getQ(), var3.getDP(), var3.getDQ(), var3.getQInv()));
      } else if (var0 instanceof DSAPrivateKeyParameters) {
         DSAPrivateKeyParameters var1 = (DSAPrivateKeyParameters)var0;
         DSAParameters var2 = var1.getParameters();
         return new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, new DSAParameter(var2.getP(), var2.getQ(), var2.getG())), new ASN1Integer(var1.getX()));
      } else {
         throw new IOException("key parameters not recognised.");
      }
   }
}
