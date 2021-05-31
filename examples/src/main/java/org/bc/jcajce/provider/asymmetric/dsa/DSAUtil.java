package org.bc.jcajce.provider.asymmetric.dsa;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.oiw.OIWObjectIdentifiers;
import org.bc.asn1.x9.X9ObjectIdentifiers;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.DSAParameters;
import org.bc.crypto.params.DSAPrivateKeyParameters;
import org.bc.crypto.params.DSAPublicKeyParameters;

public class DSAUtil {
   public static final ASN1ObjectIdentifier[] dsaOids;

   static {
      dsaOids = new ASN1ObjectIdentifier[]{X9ObjectIdentifiers.id_dsa, OIWObjectIdentifiers.dsaWithSHA1};
   }

   public static boolean isDsaOid(ASN1ObjectIdentifier var0) {
      for(int var1 = 0; var1 != dsaOids.length; ++var1) {
         if (var0.equals(dsaOids[var1])) {
            return true;
         }
      }

      return false;
   }

   public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey var0) throws InvalidKeyException {
      if (var0 instanceof DSAPublicKey) {
         DSAPublicKey var1 = (DSAPublicKey)var0;
         return new DSAPublicKeyParameters(var1.getY(), new DSAParameters(var1.getParams().getP(), var1.getParams().getQ(), var1.getParams().getG()));
      } else {
         throw new InvalidKeyException("can't identify DSA public key: " + var0.getClass().getName());
      }
   }

   public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey var0) throws InvalidKeyException {
      if (var0 instanceof DSAPrivateKey) {
         DSAPrivateKey var1 = (DSAPrivateKey)var0;
         return new DSAPrivateKeyParameters(var1.getX(), new DSAParameters(var1.getParams().getP(), var1.getParams().getQ(), var1.getParams().getG()));
      } else {
         throw new InvalidKeyException("can't identify DSA private key.");
      }
   }
}
