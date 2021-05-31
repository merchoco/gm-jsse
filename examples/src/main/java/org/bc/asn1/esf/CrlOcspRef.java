package org.bc.asn1.esf;

import java.util.Enumeration;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERSequence;
import org.bc.asn1.DERTaggedObject;

public class CrlOcspRef extends ASN1Object {
   private CrlListID crlids;
   private OcspListID ocspids;
   private OtherRevRefs otherRev;

   public static CrlOcspRef getInstance(Object var0) {
      if (var0 instanceof CrlOcspRef) {
         return (CrlOcspRef)var0;
      } else {
         return var0 != null ? new CrlOcspRef(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   private CrlOcspRef(ASN1Sequence var1) {
      Enumeration var2 = var1.getObjects();

      while(var2.hasMoreElements()) {
         DERTaggedObject var3 = (DERTaggedObject)var2.nextElement();
         switch(var3.getTagNo()) {
         case 0:
            this.crlids = CrlListID.getInstance(var3.getObject());
            break;
         case 1:
            this.ocspids = OcspListID.getInstance(var3.getObject());
            break;
         case 2:
            this.otherRev = OtherRevRefs.getInstance(var3.getObject());
            break;
         default:
            throw new IllegalArgumentException("illegal tag");
         }
      }

   }

   public CrlOcspRef(CrlListID var1, OcspListID var2, OtherRevRefs var3) {
      this.crlids = var1;
      this.ocspids = var2;
      this.otherRev = var3;
   }

   public CrlListID getCrlids() {
      return this.crlids;
   }

   public OcspListID getOcspids() {
      return this.ocspids;
   }

   public OtherRevRefs getOtherRev() {
      return this.otherRev;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      if (this.crlids != null) {
         var1.add(new DERTaggedObject(true, 0, this.crlids.toASN1Primitive()));
      }

      if (this.ocspids != null) {
         var1.add(new DERTaggedObject(true, 1, this.ocspids.toASN1Primitive()));
      }

      if (this.otherRev != null) {
         var1.add(new DERTaggedObject(true, 2, this.otherRev.toASN1Primitive()));
      }

      return new DERSequence(var1);
   }
}
