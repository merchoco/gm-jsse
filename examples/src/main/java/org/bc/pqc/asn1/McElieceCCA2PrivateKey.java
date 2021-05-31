package org.bc.pqc.asn1;

import java.math.BigInteger;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.DERSequence;
import org.bc.pqc.math.linearalgebra.GF2Matrix;
import org.bc.pqc.math.linearalgebra.GF2mField;
import org.bc.pqc.math.linearalgebra.Permutation;
import org.bc.pqc.math.linearalgebra.PolynomialGF2mSmallM;

public class McElieceCCA2PrivateKey extends ASN1Object {
   private ASN1ObjectIdentifier oid;
   private int n;
   private int k;
   private byte[] encField;
   private byte[] encGp;
   private byte[] encP;
   private byte[] encH;
   private byte[][] encqInv;

   public McElieceCCA2PrivateKey(ASN1ObjectIdentifier var1, int var2, int var3, GF2mField var4, PolynomialGF2mSmallM var5, Permutation var6, GF2Matrix var7, PolynomialGF2mSmallM[] var8) {
      this.oid = var1;
      this.n = var2;
      this.k = var3;
      this.encField = var4.getEncoded();
      this.encGp = var5.getEncoded();
      this.encP = var6.getEncoded();
      this.encH = var7.getEncoded();
      this.encqInv = new byte[var8.length][];

      for(int var9 = 0; var9 != var8.length; ++var9) {
         this.encqInv[var9] = var8[var9].getEncoded();
      }

   }

   private McElieceCCA2PrivateKey(ASN1Sequence var1) {
      this.oid = (ASN1ObjectIdentifier)var1.getObjectAt(0);
      BigInteger var2 = ((ASN1Integer)var1.getObjectAt(1)).getValue();
      this.n = var2.intValue();
      BigInteger var3 = ((ASN1Integer)var1.getObjectAt(2)).getValue();
      this.k = var3.intValue();
      this.encField = ((ASN1OctetString)var1.getObjectAt(3)).getOctets();
      this.encGp = ((ASN1OctetString)var1.getObjectAt(4)).getOctets();
      this.encP = ((ASN1OctetString)var1.getObjectAt(5)).getOctets();
      this.encH = ((ASN1OctetString)var1.getObjectAt(6)).getOctets();
      ASN1Sequence var4 = (ASN1Sequence)var1.getObjectAt(7);
      this.encqInv = new byte[var4.size()][];

      for(int var5 = 0; var5 < var4.size(); ++var5) {
         this.encqInv[var5] = ((ASN1OctetString)var4.getObjectAt(var5)).getOctets();
      }

   }

   public ASN1ObjectIdentifier getOID() {
      return this.oid;
   }

   public int getN() {
      return this.n;
   }

   public int getK() {
      return this.k;
   }

   public GF2mField getField() {
      return new GF2mField(this.encField);
   }

   public PolynomialGF2mSmallM getGoppaPoly() {
      return new PolynomialGF2mSmallM(this.getField(), this.encGp);
   }

   public Permutation getP() {
      return new Permutation(this.encP);
   }

   public GF2Matrix getH() {
      return new GF2Matrix(this.encH);
   }

   public PolynomialGF2mSmallM[] getQInv() {
      PolynomialGF2mSmallM[] var1 = new PolynomialGF2mSmallM[this.encqInv.length];
      GF2mField var2 = this.getField();

      for(int var3 = 0; var3 < this.encqInv.length; ++var3) {
         var1[var3] = new PolynomialGF2mSmallM(var2, this.encqInv[var3]);
      }

      return var1;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.oid);
      var1.add(new ASN1Integer((long)this.n));
      var1.add(new ASN1Integer((long)this.k));
      var1.add(new DEROctetString(this.encField));
      var1.add(new DEROctetString(this.encGp));
      var1.add(new DEROctetString(this.encP));
      var1.add(new DEROctetString(this.encH));
      ASN1EncodableVector var2 = new ASN1EncodableVector();

      for(int var3 = 0; var3 < this.encqInv.length; ++var3) {
         var2.add(new DEROctetString(this.encqInv[var3]));
      }

      var1.add(new DERSequence(var2));
      return new DERSequence(var1);
   }

   public static McElieceCCA2PrivateKey getInstance(Object var0) {
      if (var0 instanceof McElieceCCA2PrivateKey) {
         return (McElieceCCA2PrivateKey)var0;
      } else {
         return var0 != null ? new McElieceCCA2PrivateKey(ASN1Sequence.getInstance(var0)) : null;
      }
   }
}
