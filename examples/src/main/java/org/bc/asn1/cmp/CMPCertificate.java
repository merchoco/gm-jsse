package org.bc.asn1.cmp;

import org.bc.asn1.ASN1Choice;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERTaggedObject;
import org.bc.asn1.x509.AttributeCertificate;
import org.bc.asn1.x509.Certificate;

public class CMPCertificate extends ASN1Object implements ASN1Choice {
   private Certificate x509v3PKCert;
   private AttributeCertificate x509v2AttrCert;

   public CMPCertificate(AttributeCertificate var1) {
      this.x509v2AttrCert = var1;
   }

   public CMPCertificate(Certificate var1) {
      if (var1.getVersionNumber() != 3) {
         throw new IllegalArgumentException("only version 3 certificates allowed");
      } else {
         this.x509v3PKCert = var1;
      }
   }

   public static CMPCertificate getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof CMPCertificate)) {
         if (!(var0 instanceof ASN1Sequence) && !(var0 instanceof byte[])) {
            if (var0 instanceof ASN1TaggedObject) {
               return new CMPCertificate(AttributeCertificate.getInstance(((ASN1TaggedObject)var0).getObject()));
            } else {
               throw new IllegalArgumentException("Invalid object: " + var0.getClass().getName());
            }
         } else {
            return new CMPCertificate(Certificate.getInstance(var0));
         }
      } else {
         return (CMPCertificate)var0;
      }
   }

   public boolean isX509v3PKCert() {
      return this.x509v3PKCert != null;
   }

   public Certificate getX509v3PKCert() {
      return this.x509v3PKCert;
   }

   public AttributeCertificate getX509v2AttrCert() {
      return this.x509v2AttrCert;
   }

   public ASN1Primitive toASN1Primitive() {
      return (ASN1Primitive)(this.x509v2AttrCert != null ? new DERTaggedObject(true, 1, this.x509v2AttrCert) : this.x509v3PKCert.toASN1Primitive());
   }
}
