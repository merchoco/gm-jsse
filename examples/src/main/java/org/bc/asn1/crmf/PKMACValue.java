package org.bc.asn1.crmf;

import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERBitString;
import org.bc.asn1.DERSequence;
import org.bc.asn1.cmp.CMPObjectIdentifiers;
import org.bc.asn1.cmp.PBMParameter;
import org.bc.asn1.x509.AlgorithmIdentifier;

public class PKMACValue extends ASN1Object {
   private AlgorithmIdentifier algId;
   private DERBitString value;

   private PKMACValue(ASN1Sequence var1) {
      this.algId = AlgorithmIdentifier.getInstance(var1.getObjectAt(0));
      this.value = DERBitString.getInstance(var1.getObjectAt(1));
   }

   public static PKMACValue getInstance(Object var0) {
      if (var0 instanceof PKMACValue) {
         return (PKMACValue)var0;
      } else {
         return var0 != null ? new PKMACValue(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   public static PKMACValue getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(ASN1Sequence.getInstance(var0, var1));
   }

   public PKMACValue(PBMParameter var1, DERBitString var2) {
      this(new AlgorithmIdentifier(CMPObjectIdentifiers.passwordBasedMac, var1), var2);
   }

   public PKMACValue(AlgorithmIdentifier var1, DERBitString var2) {
      this.algId = var1;
      this.value = var2;
   }

   public AlgorithmIdentifier getAlgId() {
      return this.algId;
   }

   public DERBitString getValue() {
      return this.value;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.algId);
      var1.add(this.value);
      return new DERSequence(var1);
   }
}
