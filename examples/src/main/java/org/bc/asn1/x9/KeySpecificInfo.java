package org.bc.asn1.x9;

import java.util.Enumeration;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERSequence;

public class KeySpecificInfo extends ASN1Object {
   private ASN1ObjectIdentifier algorithm;
   private ASN1OctetString counter;

   public KeySpecificInfo(ASN1ObjectIdentifier var1, ASN1OctetString var2) {
      this.algorithm = var1;
      this.counter = var2;
   }

   public KeySpecificInfo(ASN1Sequence var1) {
      Enumeration var2 = var1.getObjects();
      this.algorithm = (ASN1ObjectIdentifier)var2.nextElement();
      this.counter = (ASN1OctetString)var2.nextElement();
   }

   public ASN1ObjectIdentifier getAlgorithm() {
      return this.algorithm;
   }

   public ASN1OctetString getCounter() {
      return this.counter;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.algorithm);
      var1.add(this.counter);
      return new DERSequence(var1);
   }
}
