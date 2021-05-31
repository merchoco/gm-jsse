package org.bc.asn1.x9;

import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1TaggedObject;

public class DHPublicKey extends ASN1Object {
   private ASN1Integer y;

   public static DHPublicKey getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(ASN1Integer.getInstance(var0, var1));
   }

   public static DHPublicKey getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof DHPublicKey)) {
         if (var0 instanceof ASN1Integer) {
            return new DHPublicKey((ASN1Integer)var0);
         } else {
            throw new IllegalArgumentException("Invalid DHPublicKey: " + var0.getClass().getName());
         }
      } else {
         return (DHPublicKey)var0;
      }
   }

   public DHPublicKey(ASN1Integer var1) {
      if (var1 == null) {
         throw new IllegalArgumentException("'y' cannot be null");
      } else {
         this.y = var1;
      }
   }

   public ASN1Integer getY() {
      return this.y;
   }

   public ASN1Primitive toASN1Primitive() {
      return this.y;
   }
}
