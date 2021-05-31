package org.bc.asn1.x509;

import java.util.Enumeration;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERSequence;
import org.bc.asn1.DERTaggedObject;

public class NameConstraints extends ASN1Object {
   private GeneralSubtree[] permitted;
   private GeneralSubtree[] excluded;

   public static NameConstraints getInstance(Object var0) {
      if (var0 instanceof NameConstraints) {
         return (NameConstraints)var0;
      } else {
         return var0 != null ? new NameConstraints(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   private NameConstraints(ASN1Sequence var1) {
      Enumeration var2 = var1.getObjects();

      while(var2.hasMoreElements()) {
         ASN1TaggedObject var3 = ASN1TaggedObject.getInstance(var2.nextElement());
         switch(var3.getTagNo()) {
         case 0:
            this.permitted = this.createArray(ASN1Sequence.getInstance(var3, false));
            break;
         case 1:
            this.excluded = this.createArray(ASN1Sequence.getInstance(var3, false));
         }
      }

   }

   public NameConstraints(GeneralSubtree[] var1, GeneralSubtree[] var2) {
      if (var1 != null) {
         this.permitted = var1;
      }

      if (var2 != null) {
         this.excluded = var2;
      }

   }

   private GeneralSubtree[] createArray(ASN1Sequence var1) {
      GeneralSubtree[] var2 = new GeneralSubtree[var1.size()];

      for(int var3 = 0; var3 != var2.length; ++var3) {
         var2[var3] = GeneralSubtree.getInstance(var1.getObjectAt(var3));
      }

      return var2;
   }

   public GeneralSubtree[] getPermittedSubtrees() {
      return this.permitted;
   }

   public GeneralSubtree[] getExcludedSubtrees() {
      return this.excluded;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      if (this.permitted != null) {
         var1.add(new DERTaggedObject(false, 0, new DERSequence(this.permitted)));
      }

      if (this.excluded != null) {
         var1.add(new DERTaggedObject(false, 1, new DERSequence(this.excluded)));
      }

      return new DERSequence(var1);
   }
}
