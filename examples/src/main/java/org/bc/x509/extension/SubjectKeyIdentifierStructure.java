package org.bc.x509.extension;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.x509.SubjectKeyIdentifier;
import org.bc.asn1.x509.SubjectPublicKeyInfo;

/** @deprecated */
public class SubjectKeyIdentifierStructure extends SubjectKeyIdentifier {
   public SubjectKeyIdentifierStructure(byte[] var1) throws IOException {
      super((ASN1OctetString)X509ExtensionUtil.fromExtensionValue(var1));
   }

   private static ASN1OctetString fromPublicKey(PublicKey var0) throws InvalidKeyException {
      try {
         SubjectPublicKeyInfo var1 = SubjectPublicKeyInfo.getInstance(var0.getEncoded());
         return (ASN1OctetString)(new SubjectKeyIdentifier(var1)).toASN1Object();
      } catch (Exception var2) {
         throw new InvalidKeyException("Exception extracting key details: " + var2.toString());
      }
   }

   public SubjectKeyIdentifierStructure(PublicKey var1) throws InvalidKeyException {
      super(fromPublicKey(var1));
   }
}
