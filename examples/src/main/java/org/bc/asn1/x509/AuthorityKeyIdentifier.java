package org.bc.asn1.x509;

import java.math.BigInteger;
import java.util.Enumeration;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.DERSequence;
import org.bc.asn1.DERTaggedObject;
import org.bc.crypto.digests.SHA1Digest;

public class AuthorityKeyIdentifier extends ASN1Object {
   ASN1OctetString keyidentifier = null;
   GeneralNames certissuer = null;
   ASN1Integer certserno = null;

   public static AuthorityKeyIdentifier getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(ASN1Sequence.getInstance(var0, var1));
   }

   public static AuthorityKeyIdentifier getInstance(Object var0) {
      if (var0 instanceof AuthorityKeyIdentifier) {
         return (AuthorityKeyIdentifier)var0;
      } else {
         return var0 != null ? new AuthorityKeyIdentifier(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   public static AuthorityKeyIdentifier fromExtensions(Extensions var0) {
      return getInstance(var0.getExtensionParsedValue(Extension.authorityKeyIdentifier));
   }

   protected AuthorityKeyIdentifier(ASN1Sequence var1) {
      Enumeration var2 = var1.getObjects();

      while(var2.hasMoreElements()) {
         ASN1TaggedObject var3 = DERTaggedObject.getInstance(var2.nextElement());
         switch(var3.getTagNo()) {
         case 0:
            this.keyidentifier = ASN1OctetString.getInstance(var3, false);
            break;
         case 1:
            this.certissuer = GeneralNames.getInstance(var3, false);
            break;
         case 2:
            this.certserno = ASN1Integer.getInstance(var3, false);
            break;
         default:
            throw new IllegalArgumentException("illegal tag");
         }
      }

   }

   public AuthorityKeyIdentifier(SubjectPublicKeyInfo var1) {
      SHA1Digest var2 = new SHA1Digest();
      byte[] var3 = new byte[var2.getDigestSize()];
      byte[] var4 = var1.getPublicKeyData().getBytes();
      var2.update(var4, 0, var4.length);
      var2.doFinal(var3, 0);
      this.keyidentifier = new DEROctetString(var3);
   }

   public AuthorityKeyIdentifier(SubjectPublicKeyInfo var1, GeneralNames var2, BigInteger var3) {
      SHA1Digest var4 = new SHA1Digest();
      byte[] var5 = new byte[var4.getDigestSize()];
      byte[] var6 = var1.getPublicKeyData().getBytes();
      var4.update(var6, 0, var6.length);
      var4.doFinal(var5, 0);
      this.keyidentifier = new DEROctetString(var5);
      this.certissuer = GeneralNames.getInstance(var2.toASN1Primitive());
      this.certserno = new ASN1Integer(var3);
   }

   public AuthorityKeyIdentifier(GeneralNames var1, BigInteger var2) {
      this.keyidentifier = null;
      this.certissuer = GeneralNames.getInstance(var1.toASN1Primitive());
      this.certserno = new ASN1Integer(var2);
   }

   public AuthorityKeyIdentifier(byte[] var1) {
      this.keyidentifier = new DEROctetString(var1);
      this.certissuer = null;
      this.certserno = null;
   }

   public AuthorityKeyIdentifier(byte[] var1, GeneralNames var2, BigInteger var3) {
      this.keyidentifier = new DEROctetString(var1);
      this.certissuer = GeneralNames.getInstance(var2.toASN1Primitive());
      this.certserno = new ASN1Integer(var3);
   }

   public byte[] getKeyIdentifier() {
      return this.keyidentifier != null ? this.keyidentifier.getOctets() : null;
   }

   public GeneralNames getAuthorityCertIssuer() {
      return this.certissuer;
   }

   public BigInteger getAuthorityCertSerialNumber() {
      return this.certserno != null ? this.certserno.getValue() : null;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      if (this.keyidentifier != null) {
         var1.add(new DERTaggedObject(false, 0, this.keyidentifier));
      }

      if (this.certissuer != null) {
         var1.add(new DERTaggedObject(false, 1, this.certissuer));
      }

      if (this.certserno != null) {
         var1.add(new DERTaggedObject(false, 2, this.certserno));
      }

      return new DERSequence(var1);
   }

   public String toString() {
      return "AuthorityKeyIdentifier: KeyID(" + this.keyidentifier.getOctets() + ")";
   }
}
