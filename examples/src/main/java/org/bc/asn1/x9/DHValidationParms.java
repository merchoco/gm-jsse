package org.bc.asn1.x9;

import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERBitString;
import org.bc.asn1.DERSequence;

public class DHValidationParms extends ASN1Object {
   private DERBitString seed;
   private ASN1Integer pgenCounter;

   public static DHValidationParms getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(ASN1Sequence.getInstance(var0, var1));
   }

   public static DHValidationParms getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof DHDomainParameters)) {
         if (var0 instanceof ASN1Sequence) {
            return new DHValidationParms((ASN1Sequence)var0);
         } else {
            throw new IllegalArgumentException("Invalid DHValidationParms: " + var0.getClass().getName());
         }
      } else {
         return (DHValidationParms)var0;
      }
   }

   public DHValidationParms(DERBitString var1, ASN1Integer var2) {
      if (var1 == null) {
         throw new IllegalArgumentException("'seed' cannot be null");
      } else if (var2 == null) {
         throw new IllegalArgumentException("'pgenCounter' cannot be null");
      } else {
         this.seed = var1;
         this.pgenCounter = var2;
      }
   }

   private DHValidationParms(ASN1Sequence var1) {
      if (var1.size() != 2) {
         throw new IllegalArgumentException("Bad sequence size: " + var1.size());
      } else {
         this.seed = DERBitString.getInstance(var1.getObjectAt(0));
         this.pgenCounter = ASN1Integer.getInstance(var1.getObjectAt(1));
      }
   }

   public DERBitString getSeed() {
      return this.seed;
   }

   public ASN1Integer getPgenCounter() {
      return this.pgenCounter;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.seed);
      var1.add(this.pgenCounter);
      return new DERSequence(var1);
   }
}
