package org.bc.asn1.cms.ecc;

import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERSequence;
import org.bc.asn1.DERTaggedObject;
import org.bc.asn1.cms.OriginatorPublicKey;

public class MQVuserKeyingMaterial extends ASN1Object {
   private OriginatorPublicKey ephemeralPublicKey;
   private ASN1OctetString addedukm;

   public MQVuserKeyingMaterial(OriginatorPublicKey var1, ASN1OctetString var2) {
      this.ephemeralPublicKey = var1;
      this.addedukm = var2;
   }

   private MQVuserKeyingMaterial(ASN1Sequence var1) {
      this.ephemeralPublicKey = OriginatorPublicKey.getInstance(var1.getObjectAt(0));
      if (var1.size() > 1) {
         this.addedukm = ASN1OctetString.getInstance((ASN1TaggedObject)var1.getObjectAt(1), true);
      }

   }

   public static MQVuserKeyingMaterial getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(ASN1Sequence.getInstance(var0, var1));
   }

   public static MQVuserKeyingMaterial getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof MQVuserKeyingMaterial)) {
         if (var0 instanceof ASN1Sequence) {
            return new MQVuserKeyingMaterial((ASN1Sequence)var0);
         } else {
            throw new IllegalArgumentException("Invalid MQVuserKeyingMaterial: " + var0.getClass().getName());
         }
      } else {
         return (MQVuserKeyingMaterial)var0;
      }
   }

   public OriginatorPublicKey getEphemeralPublicKey() {
      return this.ephemeralPublicKey;
   }

   public ASN1OctetString getAddedukm() {
      return this.addedukm;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.ephemeralPublicKey);
      if (this.addedukm != null) {
         var1.add(new DERTaggedObject(true, 0, this.addedukm));
      }

      return new DERSequence(var1);
   }
}
