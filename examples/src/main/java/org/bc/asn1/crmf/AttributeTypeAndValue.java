package org.bc.asn1.crmf;

import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERSequence;

public class AttributeTypeAndValue extends ASN1Object {
   private ASN1ObjectIdentifier type;
   private ASN1Encodable value;

   private AttributeTypeAndValue(ASN1Sequence var1) {
      this.type = (ASN1ObjectIdentifier)var1.getObjectAt(0);
      this.value = var1.getObjectAt(1);
   }

   public static AttributeTypeAndValue getInstance(Object var0) {
      if (var0 instanceof AttributeTypeAndValue) {
         return (AttributeTypeAndValue)var0;
      } else {
         return var0 != null ? new AttributeTypeAndValue(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   public AttributeTypeAndValue(String var1, ASN1Encodable var2) {
      this(new ASN1ObjectIdentifier(var1), var2);
   }

   public AttributeTypeAndValue(ASN1ObjectIdentifier var1, ASN1Encodable var2) {
      this.type = var1;
      this.value = var2;
   }

   public ASN1ObjectIdentifier getType() {
      return this.type;
   }

   public ASN1Encodable getValue() {
      return this.value;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.type);
      var1.add(this.value);
      return new DERSequence(var1);
   }
}
