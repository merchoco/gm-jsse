package org.bc.asn1.x509;

import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERSequence;
import org.bc.asn1.DERTaggedObject;

public class V2Form extends ASN1Object {
   GeneralNames issuerName;
   IssuerSerial baseCertificateID;
   ObjectDigestInfo objectDigestInfo;

   public static V2Form getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(ASN1Sequence.getInstance(var0, var1));
   }

   public static V2Form getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof V2Form)) {
         if (var0 instanceof ASN1Sequence) {
            return new V2Form((ASN1Sequence)var0);
         } else {
            throw new IllegalArgumentException("unknown object in factory: " + var0.getClass().getName());
         }
      } else {
         return (V2Form)var0;
      }
   }

   public V2Form(GeneralNames var1) {
      this.issuerName = var1;
   }

   public V2Form(ASN1Sequence var1) {
      if (var1.size() > 3) {
         throw new IllegalArgumentException("Bad sequence size: " + var1.size());
      } else {
         int var2 = 0;
         if (!(var1.getObjectAt(0) instanceof ASN1TaggedObject)) {
            ++var2;
            this.issuerName = GeneralNames.getInstance(var1.getObjectAt(0));
         }

         for(int var3 = var2; var3 != var1.size(); ++var3) {
            ASN1TaggedObject var4 = ASN1TaggedObject.getInstance(var1.getObjectAt(var3));
            if (var4.getTagNo() == 0) {
               this.baseCertificateID = IssuerSerial.getInstance(var4, false);
            } else {
               if (var4.getTagNo() != 1) {
                  throw new IllegalArgumentException("Bad tag number: " + var4.getTagNo());
               }

               this.objectDigestInfo = ObjectDigestInfo.getInstance(var4, false);
            }
         }

      }
   }

   public GeneralNames getIssuerName() {
      return this.issuerName;
   }

   public IssuerSerial getBaseCertificateID() {
      return this.baseCertificateID;
   }

   public ObjectDigestInfo getObjectDigestInfo() {
      return this.objectDigestInfo;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      if (this.issuerName != null) {
         var1.add(this.issuerName);
      }

      if (this.baseCertificateID != null) {
         var1.add(new DERTaggedObject(false, 0, this.baseCertificateID));
      }

      if (this.objectDigestInfo != null) {
         var1.add(new DERTaggedObject(false, 1, this.objectDigestInfo));
      }

      return new DERSequence(var1);
   }
}
