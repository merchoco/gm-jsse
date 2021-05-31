package org.bc.asn1.pkcs;

import java.util.Enumeration;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERSequence;

public class PBES2Parameters extends ASN1Object implements PKCSObjectIdentifiers {
   private KeyDerivationFunc func;
   private EncryptionScheme scheme;

   public static PBES2Parameters getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof PBES2Parameters)) {
         if (var0 instanceof ASN1Sequence) {
            return new PBES2Parameters((ASN1Sequence)var0);
         } else {
            throw new IllegalArgumentException("unknown object in factory: " + var0.getClass().getName());
         }
      } else {
         return (PBES2Parameters)var0;
      }
   }

   public PBES2Parameters(ASN1Sequence var1) {
      Enumeration var2 = var1.getObjects();
      ASN1Sequence var3 = ASN1Sequence.getInstance(((ASN1Encodable)var2.nextElement()).toASN1Primitive());
      if (var3.getObjectAt(0).equals(id_PBKDF2)) {
         this.func = new KeyDerivationFunc(id_PBKDF2, PBKDF2Params.getInstance(var3.getObjectAt(1)));
      } else {
         this.func = new KeyDerivationFunc(var3);
      }

      this.scheme = (EncryptionScheme)EncryptionScheme.getInstance(var2.nextElement());
   }

   public KeyDerivationFunc getKeyDerivationFunc() {
      return this.func;
   }

   public EncryptionScheme getEncryptionScheme() {
      return this.scheme;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.func);
      var1.add(this.scheme);
      return new DERSequence(var1);
   }
}
