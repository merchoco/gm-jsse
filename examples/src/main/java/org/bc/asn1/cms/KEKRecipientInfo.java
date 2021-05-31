package org.bc.asn1.cms;

import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERSequence;
import org.bc.asn1.x509.AlgorithmIdentifier;

public class KEKRecipientInfo extends ASN1Object {
   private ASN1Integer version;
   private KEKIdentifier kekid;
   private AlgorithmIdentifier keyEncryptionAlgorithm;
   private ASN1OctetString encryptedKey;

   public KEKRecipientInfo(KEKIdentifier var1, AlgorithmIdentifier var2, ASN1OctetString var3) {
      this.version = new ASN1Integer(4L);
      this.kekid = var1;
      this.keyEncryptionAlgorithm = var2;
      this.encryptedKey = var3;
   }

   public KEKRecipientInfo(ASN1Sequence var1) {
      this.version = (ASN1Integer)var1.getObjectAt(0);
      this.kekid = KEKIdentifier.getInstance(var1.getObjectAt(1));
      this.keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(var1.getObjectAt(2));
      this.encryptedKey = (ASN1OctetString)var1.getObjectAt(3);
   }

   public static KEKRecipientInfo getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(ASN1Sequence.getInstance(var0, var1));
   }

   public static KEKRecipientInfo getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof KEKRecipientInfo)) {
         if (var0 instanceof ASN1Sequence) {
            return new KEKRecipientInfo((ASN1Sequence)var0);
         } else {
            throw new IllegalArgumentException("Invalid KEKRecipientInfo: " + var0.getClass().getName());
         }
      } else {
         return (KEKRecipientInfo)var0;
      }
   }

   public ASN1Integer getVersion() {
      return this.version;
   }

   public KEKIdentifier getKekid() {
      return this.kekid;
   }

   public AlgorithmIdentifier getKeyEncryptionAlgorithm() {
      return this.keyEncryptionAlgorithm;
   }

   public ASN1OctetString getEncryptedKey() {
      return this.encryptedKey;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.version);
      var1.add(this.kekid);
      var1.add(this.keyEncryptionAlgorithm);
      var1.add(this.encryptedKey);
      return new DERSequence(var1);
   }
}
