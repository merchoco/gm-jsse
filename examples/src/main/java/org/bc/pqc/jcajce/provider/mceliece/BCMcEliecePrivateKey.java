package org.bc.pqc.jcajce.provider.mceliece;

import java.io.IOException;
import java.security.PrivateKey;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.DERNull;
import org.bc.asn1.pkcs.PrivateKeyInfo;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.crypto.CipherParameters;
import org.bc.pqc.asn1.McEliecePrivateKey;
import org.bc.pqc.crypto.mceliece.McElieceParameters;
import org.bc.pqc.crypto.mceliece.McEliecePrivateKeyParameters;
import org.bc.pqc.jcajce.spec.McEliecePrivateKeySpec;
import org.bc.pqc.math.linearalgebra.GF2Matrix;
import org.bc.pqc.math.linearalgebra.GF2mField;
import org.bc.pqc.math.linearalgebra.Permutation;
import org.bc.pqc.math.linearalgebra.PolynomialGF2mSmallM;

public class BCMcEliecePrivateKey implements CipherParameters, PrivateKey {
   private static final long serialVersionUID = 1L;
   private String oid;
   private int n;
   private int k;
   private GF2mField field;
   private PolynomialGF2mSmallM goppaPoly;
   private GF2Matrix sInv;
   private Permutation p1;
   private Permutation p2;
   private GF2Matrix h;
   private PolynomialGF2mSmallM[] qInv;
   private McElieceParameters mcElieceParams;

   public BCMcEliecePrivateKey(String var1, int var2, int var3, GF2mField var4, PolynomialGF2mSmallM var5, GF2Matrix var6, Permutation var7, Permutation var8, GF2Matrix var9, PolynomialGF2mSmallM[] var10) {
      this.oid = var1;
      this.n = var2;
      this.k = var3;
      this.field = var4;
      this.goppaPoly = var5;
      this.sInv = var6;
      this.p1 = var7;
      this.p2 = var8;
      this.h = var9;
      this.qInv = var10;
   }

   public BCMcEliecePrivateKey(McEliecePrivateKeySpec var1) {
      this(var1.getOIDString(), var1.getN(), var1.getK(), var1.getField(), var1.getGoppaPoly(), var1.getSInv(), var1.getP1(), var1.getP2(), var1.getH(), var1.getQInv());
   }

   public BCMcEliecePrivateKey(McEliecePrivateKeyParameters var1) {
      this(var1.getOIDString(), var1.getN(), var1.getK(), var1.getField(), var1.getGoppaPoly(), var1.getSInv(), var1.getP1(), var1.getP2(), var1.getH(), var1.getQInv());
      this.mcElieceParams = var1.getParameters();
   }

   public String getAlgorithm() {
      return "McEliece";
   }

   public int getN() {
      return this.n;
   }

   public int getK() {
      return this.k;
   }

   public GF2mField getField() {
      return this.field;
   }

   public PolynomialGF2mSmallM getGoppaPoly() {
      return this.goppaPoly;
   }

   public GF2Matrix getSInv() {
      return this.sInv;
   }

   public Permutation getP1() {
      return this.p1;
   }

   public Permutation getP2() {
      return this.p2;
   }

   public GF2Matrix getH() {
      return this.h;
   }

   public PolynomialGF2mSmallM[] getQInv() {
      return this.qInv;
   }

   public String getOIDString() {
      return this.oid;
   }

   public String toString() {
      String var1 = " length of the code          : " + this.n + "\n";
      var1 = var1 + " dimension of the code       : " + this.k + "\n";
      var1 = var1 + " irreducible Goppa polynomial: " + this.goppaPoly + "\n";
      var1 = var1 + " (k x k)-matrix S^-1         : " + this.sInv + "\n";
      var1 = var1 + " permutation P1              : " + this.p1 + "\n";
      var1 = var1 + " permutation P2              : " + this.p2;
      return var1;
   }

   public boolean equals(Object var1) {
      if (!(var1 instanceof BCMcEliecePrivateKey)) {
         return false;
      } else {
         BCMcEliecePrivateKey var2 = (BCMcEliecePrivateKey)var1;
         return this.n == var2.n && this.k == var2.k && this.field.equals(var2.field) && this.goppaPoly.equals(var2.goppaPoly) && this.sInv.equals(var2.sInv) && this.p1.equals(var2.p1) && this.p2.equals(var2.p2) && this.h.equals(var2.h);
      }
   }

   public int hashCode() {
      return this.k + this.n + this.field.hashCode() + this.goppaPoly.hashCode() + this.sInv.hashCode() + this.p1.hashCode() + this.p2.hashCode() + this.h.hashCode();
   }

   protected ASN1ObjectIdentifier getOID() {
      return new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.1");
   }

   protected ASN1Primitive getAlgParams() {
      return null;
   }

   public byte[] getEncoded() {
      McEliecePrivateKey var1 = new McEliecePrivateKey(new ASN1ObjectIdentifier(this.oid), this.n, this.k, this.field, this.goppaPoly, this.sInv, this.p1, this.p2, this.h, this.qInv);

      PrivateKeyInfo var2;
      try {
         AlgorithmIdentifier var3 = new AlgorithmIdentifier(this.getOID(), DERNull.INSTANCE);
         var2 = new PrivateKeyInfo(var3, var1);
      } catch (IOException var5) {
         var5.printStackTrace();
         return null;
      }

      try {
         byte[] var6 = var2.getEncoded();
         return var6;
      } catch (IOException var4) {
         var4.printStackTrace();
         return null;
      }
   }

   public String getFormat() {
      return null;
   }

   public McElieceParameters getMcElieceParameters() {
      return this.mcElieceParams;
   }
}
