package org.bc.asn1.x9;

import org.bc.asn1.ASN1Choice;
import org.bc.asn1.ASN1Null;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1TaggedObject;

public class X962Parameters extends ASN1Object implements ASN1Choice {
   private ASN1Primitive params = null;

   public static X962Parameters getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof X962Parameters)) {
         if (var0 instanceof ASN1Primitive) {
            return new X962Parameters((ASN1Primitive)var0);
         } else {
            throw new IllegalArgumentException("unknown object in getInstance()");
         }
      } else {
         return (X962Parameters)var0;
      }
   }

   public static X962Parameters getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(var0.getObject());
   }

   public X962Parameters(X9ECParameters var1) {
      this.params = var1.toASN1Primitive();
   }

   public X962Parameters(ASN1ObjectIdentifier var1) {
      this.params = var1;
   }

   public X962Parameters(ASN1Primitive var1) {
      this.params = var1;
   }

   public boolean isNamedCurve() {
      return this.params instanceof ASN1ObjectIdentifier;
   }

   public boolean isImplicitlyCA() {
      return this.params instanceof ASN1Null;
   }

   public ASN1Primitive getParameters() {
      return this.params;
   }

   public ASN1Primitive toASN1Primitive() {
      return this.params;
   }
}
