package org.bc.asn1.cms;

import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERSequence;

public class OtherKeyAttribute extends ASN1Object {
   private ASN1ObjectIdentifier keyAttrId;
   private ASN1Encodable keyAttr;

   public static OtherKeyAttribute getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof OtherKeyAttribute)) {
         if (var0 instanceof ASN1Sequence) {
            return new OtherKeyAttribute((ASN1Sequence)var0);
         } else {
            throw new IllegalArgumentException("unknown object in factory: " + var0.getClass().getName());
         }
      } else {
         return (OtherKeyAttribute)var0;
      }
   }

   public OtherKeyAttribute(ASN1Sequence var1) {
      this.keyAttrId = (ASN1ObjectIdentifier)var1.getObjectAt(0);
      this.keyAttr = var1.getObjectAt(1);
   }

   public OtherKeyAttribute(ASN1ObjectIdentifier var1, ASN1Encodable var2) {
      this.keyAttrId = var1;
      this.keyAttr = var2;
   }

   public ASN1ObjectIdentifier getKeyAttrId() {
      return this.keyAttrId;
   }

   public ASN1Encodable getKeyAttr() {
      return this.keyAttr;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.keyAttrId);
      var1.add(this.keyAttr);
      return new DERSequence(var1);
   }
}
