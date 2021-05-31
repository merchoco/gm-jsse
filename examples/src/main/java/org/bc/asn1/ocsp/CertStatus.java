package org.bc.asn1.ocsp;

import org.bc.asn1.ASN1Choice;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERNull;
import org.bc.asn1.DERTaggedObject;

public class CertStatus extends ASN1Object implements ASN1Choice {
   private int tagNo;
   private ASN1Encodable value;

   public CertStatus() {
      this.tagNo = 0;
      this.value = DERNull.INSTANCE;
   }

   public CertStatus(RevokedInfo var1) {
      this.tagNo = 1;
      this.value = var1;
   }

   public CertStatus(int var1, ASN1Encodable var2) {
      this.tagNo = var1;
      this.value = var2;
   }

   public CertStatus(ASN1TaggedObject var1) {
      this.tagNo = var1.getTagNo();
      switch(var1.getTagNo()) {
      case 0:
         this.value = DERNull.INSTANCE;
         break;
      case 1:
         this.value = RevokedInfo.getInstance(var1, false);
         break;
      case 2:
         this.value = DERNull.INSTANCE;
      }

   }

   public static CertStatus getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof CertStatus)) {
         if (var0 instanceof ASN1TaggedObject) {
            return new CertStatus((ASN1TaggedObject)var0);
         } else {
            throw new IllegalArgumentException("unknown object in factory: " + var0.getClass().getName());
         }
      } else {
         return (CertStatus)var0;
      }
   }

   public static CertStatus getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(var0.getObject());
   }

   public int getTagNo() {
      return this.tagNo;
   }

   public ASN1Encodable getStatus() {
      return this.value;
   }

   public ASN1Primitive toASN1Primitive() {
      return new DERTaggedObject(false, this.tagNo, this.value);
   }
}
