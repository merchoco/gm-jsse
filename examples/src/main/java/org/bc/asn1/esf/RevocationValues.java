package org.bc.asn1.esf;

import java.util.Enumeration;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERSequence;
import org.bc.asn1.DERTaggedObject;
import org.bc.asn1.ocsp.BasicOCSPResponse;
import org.bc.asn1.x509.CertificateList;

public class RevocationValues extends ASN1Object {
   private ASN1Sequence crlVals;
   private ASN1Sequence ocspVals;
   private OtherRevVals otherRevVals;

   public static RevocationValues getInstance(Object var0) {
      if (var0 instanceof RevocationValues) {
         return (RevocationValues)var0;
      } else {
         return var0 != null ? new RevocationValues(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   private RevocationValues(ASN1Sequence var1) {
      if (var1.size() > 3) {
         throw new IllegalArgumentException("Bad sequence size: " + var1.size());
      } else {
         Enumeration var2 = var1.getObjects();

         while(var2.hasMoreElements()) {
            DERTaggedObject var3 = (DERTaggedObject)var2.nextElement();
            switch(var3.getTagNo()) {
            case 0:
               ASN1Sequence var4 = (ASN1Sequence)var3.getObject();
               Enumeration var5 = var4.getObjects();

               while(var5.hasMoreElements()) {
                  CertificateList.getInstance(var5.nextElement());
               }

               this.crlVals = var4;
               break;
            case 1:
               ASN1Sequence var6 = (ASN1Sequence)var3.getObject();
               Enumeration var7 = var6.getObjects();

               while(var7.hasMoreElements()) {
                  BasicOCSPResponse.getInstance(var7.nextElement());
               }

               this.ocspVals = var6;
               break;
            case 2:
               this.otherRevVals = OtherRevVals.getInstance(var3.getObject());
               break;
            default:
               throw new IllegalArgumentException("invalid tag: " + var3.getTagNo());
            }
         }

      }
   }

   public RevocationValues(CertificateList[] var1, BasicOCSPResponse[] var2, OtherRevVals var3) {
      if (var1 != null) {
         this.crlVals = new DERSequence(var1);
      }

      if (var2 != null) {
         this.ocspVals = new DERSequence(var2);
      }

      this.otherRevVals = var3;
   }

   public CertificateList[] getCrlVals() {
      if (this.crlVals == null) {
         return new CertificateList[0];
      } else {
         CertificateList[] var1 = new CertificateList[this.crlVals.size()];

         for(int var2 = 0; var2 < var1.length; ++var2) {
            var1[var2] = CertificateList.getInstance(this.crlVals.getObjectAt(var2));
         }

         return var1;
      }
   }

   public BasicOCSPResponse[] getOcspVals() {
      if (this.ocspVals == null) {
         return new BasicOCSPResponse[0];
      } else {
         BasicOCSPResponse[] var1 = new BasicOCSPResponse[this.ocspVals.size()];

         for(int var2 = 0; var2 < var1.length; ++var2) {
            var1[var2] = BasicOCSPResponse.getInstance(this.ocspVals.getObjectAt(var2));
         }

         return var1;
      }
   }

   public OtherRevVals getOtherRevVals() {
      return this.otherRevVals;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      if (this.crlVals != null) {
         var1.add(new DERTaggedObject(true, 0, this.crlVals));
      }

      if (this.ocspVals != null) {
         var1.add(new DERTaggedObject(true, 1, this.ocspVals));
      }

      if (this.otherRevVals != null) {
         var1.add(new DERTaggedObject(true, 2, this.otherRevVals.toASN1Primitive()));
      }

      return new DERSequence(var1);
   }
}
