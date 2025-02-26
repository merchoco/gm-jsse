package org.bc.asn1.ocsp;

import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1GeneralizedTime;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DEREnumerated;
import org.bc.asn1.DERSequence;
import org.bc.asn1.DERTaggedObject;
import org.bc.asn1.x509.CRLReason;

public class RevokedInfo extends ASN1Object {
   private ASN1GeneralizedTime revocationTime;
   private CRLReason revocationReason;

   public RevokedInfo(ASN1GeneralizedTime var1, CRLReason var2) {
      this.revocationTime = var1;
      this.revocationReason = var2;
   }

   private RevokedInfo(ASN1Sequence var1) {
      this.revocationTime = ASN1GeneralizedTime.getInstance(var1.getObjectAt(0));
      if (var1.size() > 1) {
         this.revocationReason = CRLReason.getInstance(DEREnumerated.getInstance((ASN1TaggedObject)var1.getObjectAt(1), true));
      }

   }

   public static RevokedInfo getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(ASN1Sequence.getInstance(var0, var1));
   }

   public static RevokedInfo getInstance(Object var0) {
      if (var0 instanceof RevokedInfo) {
         return (RevokedInfo)var0;
      } else {
         return var0 != null ? new RevokedInfo(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   public ASN1GeneralizedTime getRevocationTime() {
      return this.revocationTime;
   }

   public CRLReason getRevocationReason() {
      return this.revocationReason;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.revocationTime);
      if (this.revocationReason != null) {
         var1.add(new DERTaggedObject(true, 0, this.revocationReason));
      }

      return new DERSequence(var1);
   }
}
