package org.bc.asn1.x9;

import java.math.BigInteger;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERSequence;

public class X9FieldID extends ASN1Object implements X9ObjectIdentifiers {
   private ASN1ObjectIdentifier id;
   private ASN1Primitive parameters;

   public X9FieldID(BigInteger var1) {
      this.id = prime_field;
      this.parameters = new ASN1Integer(var1);
   }

   public X9FieldID(int var1, int var2, int var3, int var4) {
      this.id = characteristic_two_field;
      ASN1EncodableVector var5 = new ASN1EncodableVector();
      var5.add(new ASN1Integer((long)var1));
      if (var3 == 0) {
         var5.add(tpBasis);
         var5.add(new ASN1Integer((long)var2));
      } else {
         var5.add(ppBasis);
         ASN1EncodableVector var6 = new ASN1EncodableVector();
         var6.add(new ASN1Integer((long)var2));
         var6.add(new ASN1Integer((long)var3));
         var6.add(new ASN1Integer((long)var4));
         var5.add(new DERSequence(var6));
      }

      this.parameters = new DERSequence(var5);
   }

   public X9FieldID(ASN1Sequence var1) {
      this.id = (ASN1ObjectIdentifier)var1.getObjectAt(0);
      this.parameters = (ASN1Primitive)var1.getObjectAt(1);
   }

   public ASN1ObjectIdentifier getIdentifier() {
      return this.id;
   }

   public ASN1Primitive getParameters() {
      return this.parameters;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.id);
      var1.add(this.parameters);
      return new DERSequence(var1);
   }
}
