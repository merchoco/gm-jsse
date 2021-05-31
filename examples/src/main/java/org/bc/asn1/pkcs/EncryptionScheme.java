package org.bc.asn1.pkcs;

import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERSequence;
import org.bc.asn1.x509.AlgorithmIdentifier;

public class EncryptionScheme extends AlgorithmIdentifier {
   public EncryptionScheme(ASN1ObjectIdentifier var1, ASN1Encodable var2) {
      super(var1, var2);
   }

   EncryptionScheme(ASN1Sequence var1) {
      this((ASN1ObjectIdentifier)var1.getObjectAt(0), var1.getObjectAt(1));
   }

   public static final AlgorithmIdentifier getInstance(Object var0) {
      if (var0 instanceof EncryptionScheme) {
         return (EncryptionScheme)var0;
      } else if (var0 instanceof ASN1Sequence) {
         return new EncryptionScheme((ASN1Sequence)var0);
      } else {
         throw new IllegalArgumentException("unknown object in factory: " + var0.getClass().getName());
      }
   }

   public ASN1Primitive getObject() {
      return (ASN1Primitive)this.getParameters();
   }

   public ASN1Primitive getASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.getObjectId());
      var1.add(this.getParameters());
      return new DERSequence(var1);
   }
}
