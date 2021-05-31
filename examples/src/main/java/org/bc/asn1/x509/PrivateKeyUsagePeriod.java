package org.bc.asn1.x509;

import java.util.Enumeration;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERGeneralizedTime;
import org.bc.asn1.DERSequence;
import org.bc.asn1.DERTaggedObject;

public class PrivateKeyUsagePeriod extends ASN1Object {
   private DERGeneralizedTime _notBefore;
   private DERGeneralizedTime _notAfter;

   public static PrivateKeyUsagePeriod getInstance(Object var0) {
      if (var0 instanceof PrivateKeyUsagePeriod) {
         return (PrivateKeyUsagePeriod)var0;
      } else {
         return var0 != null ? new PrivateKeyUsagePeriod(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   private PrivateKeyUsagePeriod(ASN1Sequence var1) {
      Enumeration var2 = var1.getObjects();

      while(var2.hasMoreElements()) {
         ASN1TaggedObject var3 = (ASN1TaggedObject)var2.nextElement();
         if (var3.getTagNo() == 0) {
            this._notBefore = DERGeneralizedTime.getInstance(var3, false);
         } else if (var3.getTagNo() == 1) {
            this._notAfter = DERGeneralizedTime.getInstance(var3, false);
         }
      }

   }

   public DERGeneralizedTime getNotBefore() {
      return this._notBefore;
   }

   public DERGeneralizedTime getNotAfter() {
      return this._notAfter;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      if (this._notBefore != null) {
         var1.add(new DERTaggedObject(false, 0, this._notBefore));
      }

      if (this._notAfter != null) {
         var1.add(new DERTaggedObject(false, 1, this._notAfter));
      }

      return new DERSequence(var1);
   }
}
