package org.bc.asn1.x9;

import java.util.Enumeration;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERSequence;
import org.bc.asn1.DERTaggedObject;

public class OtherInfo extends ASN1Object {
   private KeySpecificInfo keyInfo;
   private ASN1OctetString partyAInfo;
   private ASN1OctetString suppPubInfo;

   public OtherInfo(KeySpecificInfo var1, ASN1OctetString var2, ASN1OctetString var3) {
      this.keyInfo = var1;
      this.partyAInfo = var2;
      this.suppPubInfo = var3;
   }

   public OtherInfo(ASN1Sequence var1) {
      Enumeration var2 = var1.getObjects();
      this.keyInfo = new KeySpecificInfo((ASN1Sequence)var2.nextElement());

      while(var2.hasMoreElements()) {
         DERTaggedObject var3 = (DERTaggedObject)var2.nextElement();
         if (var3.getTagNo() == 0) {
            this.partyAInfo = (ASN1OctetString)var3.getObject();
         } else if (var3.getTagNo() == 2) {
            this.suppPubInfo = (ASN1OctetString)var3.getObject();
         }
      }

   }

   public KeySpecificInfo getKeyInfo() {
      return this.keyInfo;
   }

   public ASN1OctetString getPartyAInfo() {
      return this.partyAInfo;
   }

   public ASN1OctetString getSuppPubInfo() {
      return this.suppPubInfo;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.keyInfo);
      if (this.partyAInfo != null) {
         var1.add(new DERTaggedObject(0, this.partyAInfo));
      }

      var1.add(new DERTaggedObject(2, this.suppPubInfo));
      return new DERSequence(var1);
   }
}
