package org.bc.pqc.jcajce.provider.mceliece;

import org.bc.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
import org.bc.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
import org.bc.pqc.math.linearalgebra.GF2Matrix;
import org.bc.pqc.math.linearalgebra.GF2Vector;
import org.bc.pqc.math.linearalgebra.GF2mField;
import org.bc.pqc.math.linearalgebra.GoppaCode;
import org.bc.pqc.math.linearalgebra.Permutation;
import org.bc.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import org.bc.pqc.math.linearalgebra.Vector;

public final class McElieceCCA2Primitives {
   public static GF2Vector encryptionPrimitive(BCMcElieceCCA2PublicKey var0, GF2Vector var1, GF2Vector var2) {
      GF2Matrix var3 = var0.getG();
      Vector var4 = var3.leftMultiplyLeftCompactForm(var1);
      return (GF2Vector)var4.add(var2);
   }

   public static GF2Vector encryptionPrimitive(McElieceCCA2PublicKeyParameters var0, GF2Vector var1, GF2Vector var2) {
      GF2Matrix var3 = var0.getMatrixG();
      Vector var4 = var3.leftMultiplyLeftCompactForm(var1);
      return (GF2Vector)var4.add(var2);
   }

   public static GF2Vector[] decryptionPrimitive(BCMcElieceCCA2PrivateKey var0, GF2Vector var1) {
      int var2 = var0.getK();
      Permutation var3 = var0.getP();
      GF2mField var4 = var0.getField();
      PolynomialGF2mSmallM var5 = var0.getGoppaPoly();
      GF2Matrix var6 = var0.getH();
      PolynomialGF2mSmallM[] var7 = var0.getQInv();
      Permutation var8 = var3.computeInverse();
      GF2Vector var9 = (GF2Vector)var1.multiply(var8);
      GF2Vector var10 = (GF2Vector)var6.rightMultiply((Vector)var9);
      GF2Vector var11 = GoppaCode.syndromeDecode(var10, var4, var5, var7);
      GF2Vector var12 = (GF2Vector)var9.add(var11);
      var12 = (GF2Vector)var12.multiply(var3);
      var11 = (GF2Vector)var11.multiply(var3);
      GF2Vector var13 = var12.extractRightVector(var2);
      return new GF2Vector[]{var13, var11};
   }

   public static GF2Vector[] decryptionPrimitive(McElieceCCA2PrivateKeyParameters var0, GF2Vector var1) {
      int var2 = var0.getK();
      Permutation var3 = var0.getP();
      GF2mField var4 = var0.getField();
      PolynomialGF2mSmallM var5 = var0.getGoppaPoly();
      GF2Matrix var6 = var0.getH();
      PolynomialGF2mSmallM[] var7 = var0.getQInv();
      Permutation var8 = var3.computeInverse();
      GF2Vector var9 = (GF2Vector)var1.multiply(var8);
      GF2Vector var10 = (GF2Vector)var6.rightMultiply((Vector)var9);
      GF2Vector var11 = GoppaCode.syndromeDecode(var10, var4, var5, var7);
      GF2Vector var12 = (GF2Vector)var9.add(var11);
      var12 = (GF2Vector)var12.multiply(var3);
      var11 = (GF2Vector)var11.multiply(var3);
      GF2Vector var13 = var12.extractRightVector(var2);
      return new GF2Vector[]{var13, var11};
   }
}
