package org.bc.asn1.sec;

import java.math.BigInteger;
import java.util.Enumeration;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERBitString;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.DERSequence;
import org.bc.asn1.DERTaggedObject;
import org.bc.util.BigIntegers;

public class ECPrivateKey extends ASN1Object {
   private ASN1Sequence seq;

   private ECPrivateKey(ASN1Sequence var1) {
      this.seq = var1;
   }

   public static ECPrivateKey getInstance(Object var0) {
      if (var0 instanceof ECPrivateKey) {
         return (ECPrivateKey)var0;
      } else {
         return var0 != null ? new ECPrivateKey(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   public ECPrivateKey(BigInteger var1) {
      byte[] var2 = BigIntegers.asUnsignedByteArray(var1);
      ASN1EncodableVector var3 = new ASN1EncodableVector();
      var3.add(new ASN1Integer(1L));
      var3.add(new DEROctetString(var2));
      this.seq = new DERSequence(var3);
   }

   public ECPrivateKey(BigInteger var1, ASN1Object var2) {
      this(var1, (DERBitString)null, var2);
   }

   public ECPrivateKey(BigInteger var1, DERBitString var2, ASN1Object var3) {
      byte[] var4 = BigIntegers.asUnsignedByteArray(var1);
      ASN1EncodableVector var5 = new ASN1EncodableVector();
      var5.add(new ASN1Integer(1L));
      var5.add(new DEROctetString(var4));
      if (var3 != null) {
         var5.add(new DERTaggedObject(true, 0, var3));
      }

      if (var2 != null) {
         var5.add(new DERTaggedObject(true, 1, var2));
      }

      this.seq = new DERSequence(var5);
   }

   public BigInteger getKey() {
      ASN1OctetString var1 = (ASN1OctetString)this.seq.getObjectAt(1);
      return new BigInteger(1, var1.getOctets());
   }

   public DERBitString getPublicKey() {
      return (DERBitString)this.getObjectInTag(1);
   }

   public ASN1Primitive getParameters() {
      return this.getObjectInTag(0);
   }

   private ASN1Primitive getObjectInTag(int var1) {
      Enumeration var2 = this.seq.getObjects();

      while(var2.hasMoreElements()) {
         ASN1Encodable var3 = (ASN1Encodable)var2.nextElement();
         if (var3 instanceof ASN1TaggedObject) {
            ASN1TaggedObject var4 = (ASN1TaggedObject)var3;
            if (var4.getTagNo() == var1) {
               return var4.getObject().toASN1Primitive();
            }
         }
      }

      return null;
   }

   public ASN1Primitive toASN1Primitive() {
      return this.seq;
   }
}
