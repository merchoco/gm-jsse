package org.bc.asn1.cms;

import org.bc.asn1.ASN1Choice;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERTaggedObject;
import org.bc.asn1.x509.SubjectKeyIdentifier;

public class OriginatorIdentifierOrKey extends ASN1Object implements ASN1Choice {
   private ASN1Encodable id;

   public OriginatorIdentifierOrKey(IssuerAndSerialNumber var1) {
      this.id = var1;
   }

   /** @deprecated */
   public OriginatorIdentifierOrKey(ASN1OctetString var1) {
      this(new SubjectKeyIdentifier(var1.getOctets()));
   }

   public OriginatorIdentifierOrKey(SubjectKeyIdentifier var1) {
      this.id = new DERTaggedObject(false, 0, var1);
   }

   public OriginatorIdentifierOrKey(OriginatorPublicKey var1) {
      this.id = new DERTaggedObject(false, 1, var1);
   }

   /** @deprecated */
   public OriginatorIdentifierOrKey(ASN1Primitive var1) {
      this.id = var1;
   }

   public static OriginatorIdentifierOrKey getInstance(ASN1TaggedObject var0, boolean var1) {
      if (!var1) {
         throw new IllegalArgumentException("Can't implicitly tag OriginatorIdentifierOrKey");
      } else {
         return getInstance(var0.getObject());
      }
   }

   public static OriginatorIdentifierOrKey getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof OriginatorIdentifierOrKey)) {
         if (var0 instanceof IssuerAndSerialNumber) {
            return new OriginatorIdentifierOrKey((IssuerAndSerialNumber)var0);
         } else if (var0 instanceof SubjectKeyIdentifier) {
            return new OriginatorIdentifierOrKey((SubjectKeyIdentifier)var0);
         } else if (var0 instanceof OriginatorPublicKey) {
            return new OriginatorIdentifierOrKey((OriginatorPublicKey)var0);
         } else if (var0 instanceof ASN1TaggedObject) {
            return new OriginatorIdentifierOrKey((ASN1TaggedObject)var0);
         } else {
            throw new IllegalArgumentException("Invalid OriginatorIdentifierOrKey: " + var0.getClass().getName());
         }
      } else {
         return (OriginatorIdentifierOrKey)var0;
      }
   }

   public ASN1Encodable getId() {
      return this.id;
   }

   public IssuerAndSerialNumber getIssuerAndSerialNumber() {
      return this.id instanceof IssuerAndSerialNumber ? (IssuerAndSerialNumber)this.id : null;
   }

   public SubjectKeyIdentifier getSubjectKeyIdentifier() {
      return this.id instanceof ASN1TaggedObject && ((ASN1TaggedObject)this.id).getTagNo() == 0 ? SubjectKeyIdentifier.getInstance((ASN1TaggedObject)this.id, false) : null;
   }

   public OriginatorPublicKey getOriginatorKey() {
      return this.id instanceof ASN1TaggedObject && ((ASN1TaggedObject)this.id).getTagNo() == 1 ? OriginatorPublicKey.getInstance((ASN1TaggedObject)this.id, false) : null;
   }

   public ASN1Primitive toASN1Primitive() {
      return this.id.toASN1Primitive();
   }
}
