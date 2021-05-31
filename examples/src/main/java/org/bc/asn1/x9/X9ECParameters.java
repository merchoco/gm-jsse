package org.bc.asn1.x9;

import java.math.BigInteger;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERSequence;
import org.bc.math.ec.ECCurve;
import org.bc.math.ec.ECPoint;

public class X9ECParameters extends ASN1Object implements X9ObjectIdentifiers {
   private static final BigInteger ONE = BigInteger.valueOf(1L);
   private X9FieldID fieldID;
   private ECCurve curve;
   private ECPoint g;
   private BigInteger n;
   private BigInteger h;
   private byte[] seed;

   private X9ECParameters(ASN1Sequence var1) {
      if (var1.getObjectAt(0) instanceof ASN1Integer && ((ASN1Integer)var1.getObjectAt(0)).getValue().equals(ONE)) {
         X9Curve var2 = new X9Curve(new X9FieldID((ASN1Sequence)var1.getObjectAt(1)), (ASN1Sequence)var1.getObjectAt(2));
         this.curve = var2.getCurve();
         this.g = (new X9ECPoint(this.curve, (ASN1OctetString)var1.getObjectAt(3))).getPoint();
         this.n = ((ASN1Integer)var1.getObjectAt(4)).getValue();
         this.seed = var2.getSeed();
         if (var1.size() == 6) {
            this.h = ((ASN1Integer)var1.getObjectAt(5)).getValue();
         }

      } else {
         throw new IllegalArgumentException("bad version in X9ECParameters");
      }
   }

   public static X9ECParameters getInstance(Object var0) {
      if (var0 instanceof X9ECParameters) {
         return (X9ECParameters)var0;
      } else {
         return var0 != null ? new X9ECParameters(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   public X9ECParameters(ECCurve var1, ECPoint var2, BigInteger var3) {
      this(var1, var2, var3, ONE, (byte[])null);
   }

   public X9ECParameters(ECCurve var1, ECPoint var2, BigInteger var3, BigInteger var4) {
      this(var1, var2, var3, var4, (byte[])null);
   }

   public X9ECParameters(ECCurve var1, ECPoint var2, BigInteger var3, BigInteger var4, byte[] var5) {
      this.curve = var1;
      this.g = var2;
      this.n = var3;
      this.h = var4;
      this.seed = var5;
      if (var1 instanceof ECCurve.Fp) {
         this.fieldID = new X9FieldID(((ECCurve.Fp)var1).getQ());
      } else if (var1 instanceof ECCurve.F2m) {
         ECCurve.F2m var6 = (ECCurve.F2m)var1;
         this.fieldID = new X9FieldID(var6.getM(), var6.getK1(), var6.getK2(), var6.getK3());
      }

   }

   public ECCurve getCurve() {
      return this.curve;
   }

   public ECPoint getG() {
      return this.g;
   }

   public BigInteger getN() {
      return this.n;
   }

   public BigInteger getH() {
      return this.h == null ? ONE : this.h;
   }

   public byte[] getSeed() {
      return this.seed;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(new ASN1Integer(1L));
      var1.add(this.fieldID);
      var1.add(new X9Curve(this.curve, this.seed));
      var1.add(new X9ECPoint(this.g));
      var1.add(new ASN1Integer(this.n));
      if (this.h != null) {
         var1.add(new ASN1Integer(this.h));
      }

      return new DERSequence(var1);
   }
}
