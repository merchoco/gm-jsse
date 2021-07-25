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

public class McEliecePrivateKey extends ASN1Object {
   private ASN1ObjectIdentifier oid;
   private int n;
   private int k;
   private byte[] encField;
   private byte[] encGp;
   private byte[] encSInv;
   private byte[] encP1;
   private byte[] encP2;
   private byte[] encH;
   private byte[][] encqInv;

   public McEliecePrivateKey(ASN1ObjectIdentifier var1, int var2, int var3, GF2mField var4, PolynomialGF2mSmallM var5, GF2Matrix var6, Permutation var7, Permutation var8, GF2Matrix var9, PolynomialGF2mSmallM[] var10) {
      this.oid = var1;
      this.n = var2;
      this.k = var3;
      this.encField = var4.getEncoded();
      this.encGp = var5.getEncoded();
      this.encSInv = var6.getEncoded();
      this.encP1 = var7.getEncoded();
      this.encP2 = var8.getEncoded();
      this.encH = var9.getEncoded();
      this.encqInv = new byte[var10.length][];

      for(int var11 = 0; var11 != var10.length; ++var11) {
         this.encqInv[var11] = var10[var11].getEncoded();
      }

   }

   public static McEliecePrivateKey getInstance(Object var0) {
      if (var0 instanceof McEliecePrivateKey) {
         return (McEliecePrivateKey)var0;
      } else {
         return var0 != null ? new McEliecePrivateKey(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   private McEliecePrivateKey(ASN1Sequence var1) {
      this.oid = (ASN1ObjectIdentifier)var1.getObjectAt(0);
      BigInteger var2 = ((ASN1Integer)var1.getObjectAt(1)).getValue();
      this.n = var2.intValue();
      BigInteger var3 = ((ASN1Integer)var1.getObjectAt(2)).getValue();
      this.k = var3.intValue();
      this.encField = ((ASN1OctetString)var1.getObjectAt(3)).getOctets();
      this.encGp = ((ASN1OctetString)var1.getObjectAt(4)).getOctets();
      this.encSInv = ((ASN1OctetString)var1.getObjectAt(5)).getOctets();
      this.encP1 = ((ASN1OctetString)var1.getObjectAt(6)).getOctets();
      this.encP2 = ((ASN1OctetString)var1.getObjectAt(7)).getOctets();
      this.encH = ((ASN1OctetString)var1.getObjectAt(8)).getOctets();
      ASN1Sequence var4 = (ASN1Sequence)var1.getObjectAt(9);
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

   public GF2Matrix getSInv() {
      return new GF2Matrix(this.encSInv);
   }

   public Permutation getP1() {
      return new Permutation(this.encP1);
   }

   public Permutation getP2() {
      return new Permutation(this.encP2);
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
      var1.add(new DEROctetString(this.encSInv));
      var1.add(new DEROctetString(this.encP1));
      var1.add(new DEROctetString(this.encP2));
      var1.add(new DEROctetString(this.encH));
      ASN1EncodableVector var2 = new ASN1EncodableVector();

      for(int var3 = 0; var3 < this.encqInv.length; ++var3) {
         var2.add(new DEROctetString(this.encqInv[var3]));
      }

      var1.add(new DERSequence(var2));
      return new DERSequence(var1);
   }
}