package org.bc.asn1.pkcs;

import java.util.Enumeration;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERSequence;
import org.bc.asn1.x509.AlgorithmIdentifier;

/** @deprecated */
public class PBES2Algorithms extends AlgorithmIdentifier implements PKCSObjectIdentifiers {
   private ASN1ObjectIdentifier objectId;
   private KeyDerivationFunc func;
   private EncryptionScheme scheme;

   public PBES2Algorithms(ASN1Sequence var1) {
      super(var1);
      Enumeration var2 = var1.getObjects();
      this.objectId = (ASN1ObjectIdentifier)var2.nextElement();
      ASN1Sequence var3 = (ASN1Sequence)var2.nextElement();
      var2 = var3.getObjects();
      ASN1Sequence var4 = (ASN1Sequence)var2.nextElement();
      if (var4.getObjectAt(0).equals(id_PBKDF2)) {
         this.func = new KeyDerivationFunc(id_PBKDF2, PBKDF2Params.getInstance(var4.getObjectAt(1)));
      } else {
         this.func = new KeyDerivationFunc(var4);
      }

      this.scheme = new EncryptionScheme((ASN1Sequence)var2.nextElement());
   }

   public ASN1ObjectIdentifier getObjectId() {
      return this.objectId;
   }

   public KeyDerivationFunc getKeyDerivationFunc() {
      return this.func;
   }

   public EncryptionScheme getEncryptionScheme() {
      return this.scheme;
   }

   public ASN1Primitive getASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      ASN1EncodableVector var2 = new ASN1EncodableVector();
      var1.add(this.objectId);
      var2.add(this.func);
      var2.add(this.scheme);
      var1.add(new DERSequence(var2));
      return new DERSequence(var1);
   }
}
