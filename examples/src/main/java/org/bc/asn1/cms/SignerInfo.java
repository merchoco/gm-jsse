package org.bc.asn1.cms;

import java.util.Enumeration;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1Set;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.DERSequence;
import org.bc.asn1.DERTaggedObject;
import org.bc.asn1.x509.AlgorithmIdentifier;

public class SignerInfo extends ASN1Object {
   private ASN1Integer version;
   private SignerIdentifier sid;
   private AlgorithmIdentifier digAlgorithm;
   private ASN1Set authenticatedAttributes;
   private AlgorithmIdentifier digEncryptionAlgorithm;
   private ASN1OctetString encryptedDigest;
   private ASN1Set unauthenticatedAttributes;

   public static SignerInfo getInstance(Object var0) throws IllegalArgumentException {
      if (var0 != null && !(var0 instanceof SignerInfo)) {
         if (var0 instanceof ASN1Sequence) {
            return new SignerInfo((ASN1Sequence)var0);
         } else {
            throw new IllegalArgumentException("unknown object in factory: " + var0.getClass().getName());
         }
      } else {
         return (SignerInfo)var0;
      }
   }

   public SignerInfo(SignerIdentifier var1, AlgorithmIdentifier var2, ASN1Set var3, AlgorithmIdentifier var4, ASN1OctetString var5, ASN1Set var6) {
      if (var1.isTagged()) {
         this.version = new ASN1Integer(3L);
      } else {
         this.version = new ASN1Integer(1L);
      }

      this.sid = var1;
      this.digAlgorithm = var2;
      this.authenticatedAttributes = var3;
      this.digEncryptionAlgorithm = var4;
      this.encryptedDigest = var5;
      this.unauthenticatedAttributes = var6;
   }

   public SignerInfo(ASN1Sequence var1) {
      Enumeration var2 = var1.getObjects();
      this.version = (ASN1Integer)var2.nextElement();
      this.sid = SignerIdentifier.getInstance(var2.nextElement());
      this.digAlgorithm = AlgorithmIdentifier.getInstance(var2.nextElement());
      Object var3 = var2.nextElement();
      if (var3 instanceof ASN1TaggedObject) {
         this.authenticatedAttributes = ASN1Set.getInstance((ASN1TaggedObject)var3, false);
         this.digEncryptionAlgorithm = AlgorithmIdentifier.getInstance(var2.nextElement());
      } else {
         this.authenticatedAttributes = null;
         this.digEncryptionAlgorithm = AlgorithmIdentifier.getInstance(var3);
      }

      this.encryptedDigest = DEROctetString.getInstance(var2.nextElement());
      if (var2.hasMoreElements()) {
         this.unauthenticatedAttributes = ASN1Set.getInstance((ASN1TaggedObject)var2.nextElement(), false);
      } else {
         this.unauthenticatedAttributes = null;
      }

   }

   public ASN1Integer getVersion() {
      return this.version;
   }

   public SignerIdentifier getSID() {
      return this.sid;
   }

   public ASN1Set getAuthenticatedAttributes() {
      return this.authenticatedAttributes;
   }

   public AlgorithmIdentifier getDigestAlgorithm() {
      return this.digAlgorithm;
   }

   public ASN1OctetString getEncryptedDigest() {
      return this.encryptedDigest;
   }

   public AlgorithmIdentifier getDigestEncryptionAlgorithm() {
      return this.digEncryptionAlgorithm;
   }

   public ASN1Set getUnauthenticatedAttributes() {
      return this.unauthenticatedAttributes;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.version);
      var1.add(this.sid);
      var1.add(this.digAlgorithm);
      if (this.authenticatedAttributes != null) {
         var1.add(new DERTaggedObject(false, 0, this.authenticatedAttributes));
      }

      var1.add(this.digEncryptionAlgorithm);
      var1.add(this.encryptedDigest);
      if (this.unauthenticatedAttributes != null) {
         var1.add(new DERTaggedObject(false, 1, this.unauthenticatedAttributes));
      }

      return new DERSequence(var1);
   }
}
