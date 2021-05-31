package org.bc.pqc.asn1;

import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.DERSequence;
import org.bc.util.Arrays;

public class GMSSPublicKey extends ASN1Object {
   private ASN1Integer version;
   private byte[] publicKey;

   private GMSSPublicKey(ASN1Sequence var1) {
      if (var1.size() != 2) {
         throw new IllegalArgumentException("size of seq = " + var1.size());
      } else {
         this.version = ASN1Integer.getInstance(var1.getObjectAt(0));
         this.publicKey = ASN1OctetString.getInstance(var1.getObjectAt(1)).getOctets();
      }
   }

   public GMSSPublicKey(byte[] var1) {
      this.version = new ASN1Integer(0L);
      this.publicKey = var1;
   }

   public static GMSSPublicKey getInstance(Object var0) {
      if (var0 instanceof GMSSPublicKey) {
         return (GMSSPublicKey)var0;
      } else {
         return var0 != null ? new GMSSPublicKey(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   public byte[] getPublicKey() {
      return Arrays.clone(this.publicKey);
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.version);
      var1.add(new DEROctetString(this.publicKey));
      return new DERSequence(var1);
   }
}
