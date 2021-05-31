package org.bc.asn1.x9;

import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.DEROctetString;
import org.bc.math.ec.ECCurve;
import org.bc.math.ec.ECPoint;

public class X9ECPoint extends ASN1Object {
   ECPoint p;

   public X9ECPoint(ECPoint var1) {
      this.p = var1;
   }

   public X9ECPoint(ECCurve var1, ASN1OctetString var2) {
      this.p = var1.decodePoint(var2.getOctets());
   }

   public ECPoint getPoint() {
      return this.p;
   }

   public ASN1Primitive toASN1Primitive() {
      return new DEROctetString(this.p.getEncoded());
   }
}
