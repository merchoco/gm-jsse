package org.bc.asn1.ocsp;

import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.DERSequence;
import org.bc.asn1.x500.X500Name;

public class ServiceLocator extends ASN1Object {
   X500Name issuer;
   ASN1Primitive locator;

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.issuer);
      if (this.locator != null) {
         var1.add(this.locator);
      }

      return new DERSequence(var1);
   }
}
