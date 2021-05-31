package org.bc.asn1.x509;

import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1SequenceParser;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERNull;
import org.bc.asn1.DERObjectIdentifier;
import org.bc.asn1.DERSequence;

public class AlgorithmIdentifier extends ASN1Object {
   private ASN1ObjectIdentifier objectId;
   private ASN1Encodable parameters;
   private boolean parametersDefined = false;

   public static AlgorithmIdentifier getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(ASN1Sequence.getInstance(var0, var1));
   }

   public static AlgorithmIdentifier getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof AlgorithmIdentifier)) {
         if (var0 instanceof ASN1ObjectIdentifier) {
            return new AlgorithmIdentifier((ASN1ObjectIdentifier)var0);
         } else if (var0 instanceof String) {
            return new AlgorithmIdentifier((String)var0);
         } else if (!(var0 instanceof ASN1Sequence) && !(var0 instanceof ASN1SequenceParser)) {
            throw new IllegalArgumentException("unknown object in factory: " + var0.getClass().getName());
         } else {
            return new AlgorithmIdentifier(ASN1Sequence.getInstance(var0));
         }
      } else {
         return (AlgorithmIdentifier)var0;
      }
   }

   public AlgorithmIdentifier(ASN1ObjectIdentifier var1) {
      this.objectId = var1;
   }

   /** @deprecated */
   public AlgorithmIdentifier(String var1) {
      this.objectId = new ASN1ObjectIdentifier(var1);
   }

   /** @deprecated */
   public AlgorithmIdentifier(DERObjectIdentifier var1) {
      this.objectId = new ASN1ObjectIdentifier(var1.getId());
   }

   /** @deprecated */
   public AlgorithmIdentifier(DERObjectIdentifier var1, ASN1Encodable var2) {
      this.parametersDefined = true;
      this.objectId = new ASN1ObjectIdentifier(var1.getId());
      this.parameters = var2;
   }

   public AlgorithmIdentifier(ASN1ObjectIdentifier var1, ASN1Encodable var2) {
      this.parametersDefined = true;
      this.objectId = var1;
      this.parameters = var2;
   }

   public AlgorithmIdentifier(ASN1Sequence var1) {
      if (var1.size() >= 1 && var1.size() <= 2) {
         this.objectId = ASN1ObjectIdentifier.getInstance(var1.getObjectAt(0));
         if (var1.size() == 2) {
            this.parametersDefined = true;
            this.parameters = var1.getObjectAt(1);
         } else {
            this.parameters = null;
         }

      } else {
         throw new IllegalArgumentException("Bad sequence size: " + var1.size());
      }
   }

   public ASN1ObjectIdentifier getAlgorithm() {
      return new ASN1ObjectIdentifier(this.objectId.getId());
   }

   /** @deprecated */
   public ASN1ObjectIdentifier getObjectId() {
      return this.objectId;
   }

   public ASN1Encodable getParameters() {
      return this.parameters;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.objectId);
      if (this.parametersDefined) {
         if (this.parameters != null) {
            var1.add(this.parameters);
         } else {
            var1.add(DERNull.INSTANCE);
         }
      }

      return new DERSequence(var1);
   }
}
