package org.bc.asn1.cms;

import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Set;
import org.bc.asn1.BERSet;

public class Attributes extends ASN1Object {
   private ASN1Set attributes;

   private Attributes(ASN1Set var1) {
      this.attributes = var1;
   }

   public Attributes(ASN1EncodableVector var1) {
      this.attributes = new BERSet(var1);
   }

   public static Attributes getInstance(Object var0) {
      if (var0 instanceof Attributes) {
         return (Attributes)var0;
      } else {
         return var0 != null ? new Attributes(ASN1Set.getInstance(var0)) : null;
      }
   }

   public ASN1Primitive toASN1Primitive() {
      return this.attributes;
   }
}
