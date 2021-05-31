package org.bc.asn1.oiw;

import java.math.BigInteger;
import java.util.Enumeration;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERSequence;

public class ElGamalParameter extends ASN1Object {
   ASN1Integer p;
   ASN1Integer g;

   public ElGamalParameter(BigInteger var1, BigInteger var2) {
      this.p = new ASN1Integer(var1);
      this.g = new ASN1Integer(var2);
   }

   public ElGamalParameter(ASN1Sequence var1) {
      Enumeration var2 = var1.getObjects();
      this.p = (ASN1Integer)var2.nextElement();
      this.g = (ASN1Integer)var2.nextElement();
   }

   public BigInteger getP() {
      return this.p.getPositiveValue();
   }

   public BigInteger getG() {
      return this.g.getPositiveValue();
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.p);
      var1.add(this.g);
      return new DERSequence(var1);
   }
}
