package org.bc.asn1.ocsp;

import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERSequence;

public class ResponseBytes extends ASN1Object {
   ASN1ObjectIdentifier responseType;
   ASN1OctetString response;

   public ResponseBytes(ASN1ObjectIdentifier var1, ASN1OctetString var2) {
      this.responseType = var1;
      this.response = var2;
   }

   public ResponseBytes(ASN1Sequence var1) {
      this.responseType = (ASN1ObjectIdentifier)var1.getObjectAt(0);
      this.response = (ASN1OctetString)var1.getObjectAt(1);
   }

   public static ResponseBytes getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(ASN1Sequence.getInstance(var0, var1));
   }

   public static ResponseBytes getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof ResponseBytes)) {
         if (var0 instanceof ASN1Sequence) {
            return new ResponseBytes((ASN1Sequence)var0);
         } else {
            throw new IllegalArgumentException("unknown object in factory: " + var0.getClass().getName());
         }
      } else {
         return (ResponseBytes)var0;
      }
   }

   public ASN1ObjectIdentifier getResponseType() {
      return this.responseType;
   }

   public ASN1OctetString getResponse() {
      return this.response;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.responseType);
      var1.add(this.response);
      return new DERSequence(var1);
   }
}
