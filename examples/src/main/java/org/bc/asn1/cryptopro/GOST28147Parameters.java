package org.bc.asn1.cryptopro;

import java.util.Enumeration;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERSequence;

public class GOST28147Parameters extends ASN1Object {
   ASN1OctetString iv;
   ASN1ObjectIdentifier paramSet;

   public static GOST28147Parameters getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(ASN1Sequence.getInstance(var0, var1));
   }

   public static GOST28147Parameters getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof GOST28147Parameters)) {
         if (var0 instanceof ASN1Sequence) {
            return new GOST28147Parameters((ASN1Sequence)var0);
         } else {
            throw new IllegalArgumentException("Invalid GOST3410Parameter: " + var0.getClass().getName());
         }
      } else {
         return (GOST28147Parameters)var0;
      }
   }

   public GOST28147Parameters(ASN1Sequence var1) {
      Enumeration var2 = var1.getObjects();
      this.iv = (ASN1OctetString)var2.nextElement();
      this.paramSet = (ASN1ObjectIdentifier)var2.nextElement();
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.iv);
      var1.add(this.paramSet);
      return new DERSequence(var1);
   }
}
