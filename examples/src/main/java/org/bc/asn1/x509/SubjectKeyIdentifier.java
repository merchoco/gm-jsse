package org.bc.asn1.x509;

import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DEROctetString;
import org.bc.crypto.digests.SHA1Digest;

public class SubjectKeyIdentifier extends ASN1Object {
   private byte[] keyidentifier;

   public static SubjectKeyIdentifier getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(ASN1OctetString.getInstance(var0, var1));
   }

   public static SubjectKeyIdentifier getInstance(Object var0) {
      if (var0 instanceof SubjectKeyIdentifier) {
         return (SubjectKeyIdentifier)var0;
      } else {
         return var0 != null ? new SubjectKeyIdentifier(ASN1OctetString.getInstance(var0)) : null;
      }
   }

   public static SubjectKeyIdentifier fromExtensions(Extensions var0) {
      return getInstance(var0.getExtensionParsedValue(Extension.subjectKeyIdentifier));
   }

   public SubjectKeyIdentifier(byte[] var1) {
      this.keyidentifier = var1;
   }

   protected SubjectKeyIdentifier(ASN1OctetString var1) {
      this.keyidentifier = var1.getOctets();
   }

   public byte[] getKeyIdentifier() {
      return this.keyidentifier;
   }

   public ASN1Primitive toASN1Primitive() {
      return new DEROctetString(this.keyidentifier);
   }

   /** @deprecated */
   public SubjectKeyIdentifier(SubjectPublicKeyInfo var1) {
      this.keyidentifier = getDigest(var1);
   }

   /** @deprecated */
   public static SubjectKeyIdentifier createSHA1KeyIdentifier(SubjectPublicKeyInfo var0) {
      return new SubjectKeyIdentifier(var0);
   }

   /** @deprecated */
   public static SubjectKeyIdentifier createTruncatedSHA1KeyIdentifier(SubjectPublicKeyInfo var0) {
      byte[] var1 = getDigest(var0);
      byte[] var2 = new byte[8];
      System.arraycopy(var1, var1.length - 8, var2, 0, var2.length);
      var2[0] = (byte)(var2[0] & 15);
      var2[0] = (byte)(var2[0] | 64);
      return new SubjectKeyIdentifier(var2);
   }

   private static byte[] getDigest(SubjectPublicKeyInfo var0) {
      SHA1Digest var1 = new SHA1Digest();
      byte[] var2 = new byte[var1.getDigestSize()];
      byte[] var3 = var0.getPublicKeyData().getBytes();
      var1.update(var3, 0, var3.length);
      var1.doFinal(var2, 0);
      return var2;
   }
}
