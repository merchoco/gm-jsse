package org.bc.asn1.cms;

import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERSequence;

public class OtherRecipientInfo extends ASN1Object {
   private ASN1ObjectIdentifier oriType;
   private ASN1Encodable oriValue;

   public OtherRecipientInfo(ASN1ObjectIdentifier var1, ASN1Encodable var2) {
      this.oriType = var1;
      this.oriValue = var2;
   }

   public OtherRecipientInfo(ASN1Sequence var1) {
      this.oriType = ASN1ObjectIdentifier.getInstance(var1.getObjectAt(0));
      this.oriValue = var1.getObjectAt(1);
   }

   public static OtherRecipientInfo getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(ASN1Sequence.getInstance(var0, var1));
   }

   public static OtherRecipientInfo getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof OtherRecipientInfo)) {
         if (var0 instanceof ASN1Sequence) {
            return new OtherRecipientInfo((ASN1Sequence)var0);
         } else {
            throw new IllegalArgumentException("Invalid OtherRecipientInfo: " + var0.getClass().getName());
         }
      } else {
         return (OtherRecipientInfo)var0;
      }
   }

   public ASN1ObjectIdentifier getType() {
      return this.oriType;
   }

   public ASN1Encodable getValue() {
      return this.oriValue;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.oriType);
      var1.add(this.oriValue);
      return new DERSequence(var1);
   }
}
