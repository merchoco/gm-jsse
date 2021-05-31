package org.bc.pqc.crypto.rainbow;

import java.security.SecureRandom;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.params.ParametersWithRandom;
import org.bc.pqc.crypto.MessageSigner;
import org.bc.pqc.crypto.rainbow.util.ComputeInField;
import org.bc.pqc.crypto.rainbow.util.GF2Field;

public class RainbowSigner implements MessageSigner {
   private SecureRandom random;
   int signableDocumentLength;
   private short[] x;
   private ComputeInField cf = new ComputeInField();
   RainbowKeyParameters key;

   public void init(boolean var1, CipherParameters var2) {
      if (var1) {
         if (var2 instanceof ParametersWithRandom) {
            ParametersWithRandom var3 = (ParametersWithRandom)var2;
            this.random = var3.getRandom();
            this.key = (RainbowPrivateKeyParameters)var3.getParameters();
         } else {
            this.random = new SecureRandom();
            this.key = (RainbowPrivateKeyParameters)var2;
         }
      } else {
         this.key = (RainbowPublicKeyParameters)var2;
      }

      this.signableDocumentLength = this.key.getDocLength();
   }

   private short[] initSign(Layer[] var1, short[] var2) {
      short[] var3 = new short[var2.length];
      var3 = this.cf.addVect(((RainbowPrivateKeyParameters)this.key).getB1(), var2);
      short[] var4 = this.cf.multiplyMatrix(((RainbowPrivateKeyParameters)this.key).getInvA1(), var3);

      for(int var5 = 0; var5 < var1[0].getVi(); ++var5) {
         this.x[var5] = (short)this.random.nextInt();
         this.x[var5] = (short)(this.x[var5] & 255);
      }

      return var4;
   }

   public byte[] generateSignature(byte[] var1) {
      Layer[] var2 = ((RainbowPrivateKeyParameters)this.key).getLayers();
      int var3 = var2.length;
      this.x = new short[((RainbowPrivateKeyParameters)this.key).getInvA2().length];
      byte[] var10 = new byte[var2[var3 - 1].getViNext()];
      short[] var11 = this.makeMessageRepresentative(var1);

      boolean var12;
      do {
         var12 = true;
         int var6 = 0;

         try {
            short[] var4 = this.initSign(var2, var11);

            int var13;
            for(var13 = 0; var13 < var3; ++var13) {
               short[] var5 = new short[var2[var13].getOi()];
               short[] var7 = new short[var2[var13].getOi()];

               int var14;
               for(var14 = 0; var14 < var2[var13].getOi(); ++var14) {
                  var5[var14] = var4[var6];
                  ++var6;
               }

               var7 = this.cf.solveEquation(var2[var13].plugInVinegars(this.x), var5);
               if (var7 == null) {
                  throw new Exception("LES is not solveable!");
               }

               for(var14 = 0; var14 < var7.length; ++var14) {
                  this.x[var2[var13].getVi() + var14] = var7[var14];
               }
            }

            short[] var8 = this.cf.addVect(((RainbowPrivateKeyParameters)this.key).getB2(), this.x);
            short[] var9 = this.cf.multiplyMatrix(((RainbowPrivateKeyParameters)this.key).getInvA2(), var8);

            for(var13 = 0; var13 < var10.length; ++var13) {
               var10[var13] = (byte)var9[var13];
            }
         } catch (Exception var15) {
            var12 = false;
         }
      } while(!var12);

      return var10;
   }

   public boolean verifySignature(byte[] var1, byte[] var2) {
      short[] var3 = new short[var2.length];

      for(int var5 = 0; var5 < var2.length; ++var5) {
         short var4 = (short)var2[var5];
         var4 = (short)(var4 & 255);
         var3[var5] = var4;
      }

      short[] var9 = this.makeMessageRepresentative(var1);
      short[] var6 = this.verifySignatureIntern(var3);
      boolean var7 = true;
      if (var9.length != var6.length) {
         return false;
      } else {
         for(int var8 = 0; var8 < var9.length; ++var8) {
            var7 = var7 && var9[var8] == var6[var8];
         }

         return var7;
      }
   }

   private short[] verifySignatureIntern(short[] var1) {
      short[][] var2 = ((RainbowPublicKeyParameters)this.key).getCoeffQuadratic();
      short[][] var3 = ((RainbowPublicKeyParameters)this.key).getCoeffSingular();
      short[] var4 = ((RainbowPublicKeyParameters)this.key).getCoeffScalar();
      short[] var5 = new short[var2.length];
      int var6 = var3[0].length;
      boolean var7 = false;
      boolean var8 = false;

      for(int var9 = 0; var9 < var2.length; ++var9) {
         int var12 = 0;

         for(int var10 = 0; var10 < var6; ++var10) {
            short var13;
            for(int var11 = var10; var11 < var6; ++var11) {
               var13 = GF2Field.multElem(var2[var9][var12], GF2Field.multElem(var1[var10], var1[var11]));
               var5[var9] = GF2Field.addElem(var5[var9], var13);
               ++var12;
            }

            var13 = GF2Field.multElem(var3[var9][var10], var1[var10]);
            var5[var9] = GF2Field.addElem(var5[var9], var13);
         }

         var5[var9] = GF2Field.addElem(var5[var9], var4[var9]);
      }

      return var5;
   }

   private short[] makeMessageRepresentative(byte[] var1) {
      short[] var2 = new short[this.signableDocumentLength];
      int var3 = 0;
      int var4 = 0;

      while(var4 < var1.length) {
         var2[var4] = (short)var1[var3];
         var2[var4] = (short)(var2[var4] & 255);
         ++var3;
         ++var4;
         if (var4 >= var2.length) {
            break;
         }
      }

      return var2;
   }
}
