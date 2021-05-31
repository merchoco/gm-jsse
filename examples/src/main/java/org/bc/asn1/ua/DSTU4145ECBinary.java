package org.bc.asn1.ua;

import java.math.BigInteger;
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
import org.bc.asn1.x9.X9IntegerConverter;
import org.bc.crypto.params.ECDomainParameters;
import org.bc.math.ec.ECCurve;
import org.bc.util.Arrays;

public class DSTU4145ECBinary extends ASN1Object {
   BigInteger version = BigInteger.valueOf(0L);
   DSTU4145BinaryField f;
   ASN1Integer a;
   ASN1OctetString b;
   ASN1Integer n;
   ASN1OctetString bp;

   public DSTU4145ECBinary(ECDomainParameters var1) {
      if (!(var1.getCurve() instanceof ECCurve.F2m)) {
         throw new IllegalArgumentException("only binary domain is possible");
      } else {
         ECCurve.F2m var2 = (ECCurve.F2m)var1.getCurve();
         this.f = new DSTU4145BinaryField(var2.getM(), var2.getK1(), var2.getK2(), var2.getK3());
         this.a = new ASN1Integer(var2.getA().toBigInteger());
         X9IntegerConverter var3 = new X9IntegerConverter();
         this.b = new DEROctetString(var3.integerToBytes(var2.getB().toBigInteger(), var3.getByteLength((ECCurve)var2)));
         this.n = new ASN1Integer(var1.getN());
         this.bp = new DEROctetString(DSTU4145PointEncoder.encodePoint(var1.getG()));
      }
   }

   private DSTU4145ECBinary(ASN1Sequence var1) {
      int var2 = 0;
      if (var1.getObjectAt(var2) instanceof ASN1TaggedObject) {
         ASN1TaggedObject var3 = (ASN1TaggedObject)var1.getObjectAt(var2);
         if (!var3.isExplicit() || var3.getTagNo() != 0) {
            throw new IllegalArgumentException("object parse error");
         }

         this.version = ASN1Integer.getInstance(var3.getLoadedObject()).getValue();
         ++var2;
      }

      this.f = DSTU4145BinaryField.getInstance(var1.getObjectAt(var2));
      ++var2;
      this.a = ASN1Integer.getInstance(var1.getObjectAt(var2));
      ++var2;
      this.b = ASN1OctetString.getInstance(var1.getObjectAt(var2));
      ++var2;
      this.n = ASN1Integer.getInstance(var1.getObjectAt(var2));
      ++var2;
      this.bp = ASN1OctetString.getInstance(var1.getObjectAt(var2));
   }

   public static DSTU4145ECBinary getInstance(Object var0) {
      if (var0 instanceof DSTU4145ECBinary) {
         return (DSTU4145ECBinary)var0;
      } else {
         return var0 != null ? new DSTU4145ECBinary(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   public DSTU4145BinaryField getField() {
      return this.f;
   }

   public BigInteger getA() {
      return this.a.getValue();
   }

   public byte[] getB() {
      return Arrays.clone(this.b.getOctets());
   }

   public BigInteger getN() {
      return this.n.getValue();
   }

   public byte[] getG() {
      return Arrays.clone(this.bp.getOctets());
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      if (this.version.compareTo(BigInteger.valueOf(0L)) != 0) {
         var1.add(new DERTaggedObject(true, 0, new ASN1Integer(this.version)));
      }

      var1.add(this.f);
      var1.add(this.a);
      var1.add(this.b);
      var1.add(this.n);
      var1.add(this.bp);
      return new DERSequence(var1);
   }
}
