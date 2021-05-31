package org.bc.asn1.cms;

import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERSequence;
import org.bc.asn1.DERTaggedObject;
import org.bc.asn1.x509.AlgorithmIdentifier;

public class KeyAgreeRecipientInfo extends ASN1Object {
   private ASN1Integer version;
   private OriginatorIdentifierOrKey originator;
   private ASN1OctetString ukm;
   private AlgorithmIdentifier keyEncryptionAlgorithm;
   private ASN1Sequence recipientEncryptedKeys;

   public KeyAgreeRecipientInfo(OriginatorIdentifierOrKey var1, ASN1OctetString var2, AlgorithmIdentifier var3, ASN1Sequence var4) {
      this.version = new ASN1Integer(3L);
      this.originator = var1;
      this.ukm = var2;
      this.keyEncryptionAlgorithm = var3;
      this.recipientEncryptedKeys = var4;
   }

   public KeyAgreeRecipientInfo(ASN1Sequence var1) {
      byte var2 = 0;
      int var3 = var2 + 1;
      this.version = (ASN1Integer)var1.getObjectAt(var2);
      this.originator = OriginatorIdentifierOrKey.getInstance((ASN1TaggedObject)var1.getObjectAt(var3++), true);
      if (var1.getObjectAt(var3) instanceof ASN1TaggedObject) {
         this.ukm = ASN1OctetString.getInstance((ASN1TaggedObject)var1.getObjectAt(var3++), true);
      }

      this.keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(var1.getObjectAt(var3++));
      this.recipientEncryptedKeys = (ASN1Sequence)var1.getObjectAt(var3++);
   }

   public static KeyAgreeRecipientInfo getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(ASN1Sequence.getInstance(var0, var1));
   }

   public static KeyAgreeRecipientInfo getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof KeyAgreeRecipientInfo)) {
         if (var0 instanceof ASN1Sequence) {
            return new KeyAgreeRecipientInfo((ASN1Sequence)var0);
         } else {
            throw new IllegalArgumentException("Illegal object in KeyAgreeRecipientInfo: " + var0.getClass().getName());
         }
      } else {
         return (KeyAgreeRecipientInfo)var0;
      }
   }

   public ASN1Integer getVersion() {
      return this.version;
   }

   public OriginatorIdentifierOrKey getOriginator() {
      return this.originator;
   }

   public ASN1OctetString getUserKeyingMaterial() {
      return this.ukm;
   }

   public AlgorithmIdentifier getKeyEncryptionAlgorithm() {
      return this.keyEncryptionAlgorithm;
   }

   public ASN1Sequence getRecipientEncryptedKeys() {
      return this.recipientEncryptedKeys;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.version);
      var1.add(new DERTaggedObject(true, 0, this.originator));
      if (this.ukm != null) {
         var1.add(new DERTaggedObject(true, 1, this.ukm));
      }

      var1.add(this.keyEncryptionAlgorithm);
      var1.add(this.recipientEncryptedKeys);
      return new DERSequence(var1);
   }
}
