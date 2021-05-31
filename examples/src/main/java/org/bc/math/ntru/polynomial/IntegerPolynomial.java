package org.bc.math.ntru.polynomial;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import org.bc.math.ntru.euclid.BigIntEuclidean;
import org.bc.math.ntru.util.ArrayEncoder;
import org.bc.math.ntru.util.Util;
import org.bc.util.Arrays;

public class IntegerPolynomial implements Polynomial {
   private static final int NUM_EQUAL_RESULTANTS = 3;
   private static final int[] PRIMES = new int[]{4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657, 4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003, 5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087, 5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279, 5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387, 5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443, 5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521, 5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591, 5623, 5639, 5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693, 5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857, 5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939, 5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053, 6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133, 6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221, 6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301, 6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367, 6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473, 6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571, 6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673, 6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761, 6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833, 6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917, 6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997, 7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103, 7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207, 7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297, 7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411, 7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499, 7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561, 7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643, 7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829, 7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919, 7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009, 8011, 8017, 8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111, 8117, 8123, 8147, 8161, 8167, 8171, 8179, 8191, 8209, 8219, 8221, 8231, 8233, 8237, 8243, 8263, 8269, 8273, 8287, 8291, 8293, 8297, 8311, 8317, 8329, 8353, 8363, 8369, 8377, 8387, 8389, 8419, 8423, 8429, 8431, 8443, 8447, 8461, 8467, 8501, 8513, 8521, 8527, 8537, 8539, 8543, 8563, 8573, 8581, 8597, 8599, 8609, 8623, 8627, 8629, 8641, 8647, 8663, 8669, 8677, 8681, 8689, 8693, 8699, 8707, 8713, 8719, 8731, 8737, 8741, 8747, 8753, 8761, 8779, 8783, 8803, 8807, 8819, 8821, 8831, 8837, 8839, 8849, 8861, 8863, 8867, 8887, 8893, 8923, 8929, 8933, 8941, 8951, 8963, 8969, 8971, 8999, 9001, 9007, 9011, 9013, 9029, 9041, 9043, 9049, 9059, 9067, 9091, 9103, 9109, 9127, 9133, 9137, 9151, 9157, 9161, 9173, 9181, 9187, 9199, 9203, 9209, 9221, 9227, 9239, 9241, 9257, 9277, 9281, 9283, 9293, 9311, 9319, 9323, 9337, 9341, 9343, 9349, 9371, 9377, 9391, 9397, 9403, 9413, 9419, 9421, 9431, 9433, 9437, 9439, 9461, 9463, 9467, 9473, 9479, 9491, 9497, 9511, 9521, 9533, 9539, 9547, 9551, 9587, 9601, 9613, 9619, 9623, 9629, 9631, 9643, 9649, 9661, 9677, 9679, 9689, 9697, 9719, 9721, 9733, 9739, 9743, 9749, 9767, 9769, 9781, 9787, 9791, 9803, 9811, 9817, 9829, 9833, 9839, 9851, 9857, 9859, 9871, 9883, 9887, 9901, 9907, 9923, 9929, 9931, 9941, 9949, 9967, 9973};
   private static final List BIGINT_PRIMES = new ArrayList();
   public int[] coeffs;

   static {
      for(int var0 = 0; var0 != PRIMES.length; ++var0) {
         BIGINT_PRIMES.add(BigInteger.valueOf((long)PRIMES[var0]));
      }

   }

   public IntegerPolynomial(int var1) {
      this.coeffs = new int[var1];
   }

   public IntegerPolynomial(int[] var1) {
      this.coeffs = var1;
   }

   public IntegerPolynomial(BigIntPolynomial var1) {
      this.coeffs = new int[var1.coeffs.length];

      for(int var2 = 0; var2 < var1.coeffs.length; ++var2) {
         this.coeffs[var2] = var1.coeffs[var2].intValue();
      }

   }

   public static IntegerPolynomial fromBinary3Sves(byte[] var0, int var1) {
      return new IntegerPolynomial(ArrayEncoder.decodeMod3Sves(var0, var1));
   }

   public static IntegerPolynomial fromBinary3Tight(byte[] var0, int var1) {
      return new IntegerPolynomial(ArrayEncoder.decodeMod3Tight(var0, var1));
   }

   public static IntegerPolynomial fromBinary3Tight(InputStream var0, int var1) throws IOException {
      return new IntegerPolynomial(ArrayEncoder.decodeMod3Tight(var0, var1));
   }

   public static IntegerPolynomial fromBinary(byte[] var0, int var1, int var2) {
      return new IntegerPolynomial(ArrayEncoder.decodeModQ(var0, var1, var2));
   }

   public static IntegerPolynomial fromBinary(InputStream var0, int var1, int var2) throws IOException {
      return new IntegerPolynomial(ArrayEncoder.decodeModQ(var0, var1, var2));
   }

   public byte[] toBinary3Sves() {
      return ArrayEncoder.encodeMod3Sves(this.coeffs);
   }

   public byte[] toBinary3Tight() {
      BigInteger var1 = Constants.BIGINT_ZERO;

      int var2;
      for(var2 = this.coeffs.length - 1; var2 >= 0; --var2) {
         var1 = var1.multiply(BigInteger.valueOf(3L));
         var1 = var1.add(BigInteger.valueOf((long)(this.coeffs[var2] + 1)));
      }

      var2 = (BigInteger.valueOf(3L).pow(this.coeffs.length).bitLength() + 7) / 8;
      byte[] var3 = var1.toByteArray();
      if (var3.length < var2) {
         byte[] var4 = new byte[var2];
         System.arraycopy(var3, 0, var4, var2 - var3.length, var3.length);
         return var4;
      } else {
         if (var3.length > var2) {
            var3 = Arrays.copyOfRange((byte[])var3, 1, var3.length);
         }

         return var3;
      }
   }

   public byte[] toBinary(int var1) {
      return ArrayEncoder.encodeModQ(this.coeffs, var1);
   }

   public IntegerPolynomial mult(IntegerPolynomial var1, int var2) {
      IntegerPolynomial var3 = this.mult(var1);
      var3.mod(var2);
      return var3;
   }

   public IntegerPolynomial mult(IntegerPolynomial var1) {
      int var2 = this.coeffs.length;
      if (var1.coeffs.length != var2) {
         throw new IllegalArgumentException("Number of coefficients must be the same");
      } else {
         IntegerPolynomial var3 = this.multRecursive(var1);
         if (var3.coeffs.length > var2) {
            for(int var4 = var2; var4 < var3.coeffs.length; ++var4) {
               var3.coeffs[var4 - var2] += var3.coeffs[var4];
            }

            var3.coeffs = Arrays.copyOf(var3.coeffs, var2);
         }

         return var3;
      }
   }

   public BigIntPolynomial mult(BigIntPolynomial var1) {
      return (new BigIntPolynomial(this)).mult(var1);
   }

   private IntegerPolynomial multRecursive(IntegerPolynomial var1) {
      int[] var2 = this.coeffs;
      int[] var3 = var1.coeffs;
      int var4 = var1.coeffs.length;
      int var5;
      IntegerPolynomial var6;
      if (var4 <= 32) {
         var5 = 2 * var4 - 1;
         var6 = new IntegerPolynomial(new int[var5]);

         for(int var17 = 0; var17 < var5; ++var17) {
            for(int var18 = Math.max(0, var17 - var4 + 1); var18 <= Math.min(var17, var4 - 1); ++var18) {
               var6.coeffs[var17] += var3[var18] * var2[var17 - var18];
            }
         }

         return var6;
      } else {
         var5 = var4 / 2;
         var6 = new IntegerPolynomial(Arrays.copyOf(var2, var5));
         IntegerPolynomial var7 = new IntegerPolynomial(Arrays.copyOfRange(var2, var5, var4));
         IntegerPolynomial var8 = new IntegerPolynomial(Arrays.copyOf(var3, var5));
         IntegerPolynomial var9 = new IntegerPolynomial(Arrays.copyOfRange(var3, var5, var4));
         IntegerPolynomial var10 = (IntegerPolynomial)var6.clone();
         var10.add(var7);
         IntegerPolynomial var11 = (IntegerPolynomial)var8.clone();
         var11.add(var9);
         IntegerPolynomial var12 = var6.multRecursive(var8);
         IntegerPolynomial var13 = var7.multRecursive(var9);
         IntegerPolynomial var14 = var10.multRecursive(var11);
         var14.sub(var12);
         var14.sub(var13);
         IntegerPolynomial var15 = new IntegerPolynomial(2 * var4 - 1);

         int var16;
         for(var16 = 0; var16 < var12.coeffs.length; ++var16) {
            var15.coeffs[var16] = var12.coeffs[var16];
         }

         for(var16 = 0; var16 < var14.coeffs.length; ++var16) {
            var15.coeffs[var5 + var16] += var14.coeffs[var16];
         }

         for(var16 = 0; var16 < var13.coeffs.length; ++var16) {
            var15.coeffs[2 * var5 + var16] += var13.coeffs[var16];
         }

         return var15;
      }
   }

   public IntegerPolynomial invertFq(int var1) {
      int var2 = this.coeffs.length;
      int var3 = 0;
      IntegerPolynomial var4 = new IntegerPolynomial(var2 + 1);
      var4.coeffs[0] = 1;
      IntegerPolynomial var5 = new IntegerPolynomial(var2 + 1);
      IntegerPolynomial var6 = new IntegerPolynomial(var2 + 1);
      var6.coeffs = Arrays.copyOf(this.coeffs, var2 + 1);
      var6.modPositive(2);
      IntegerPolynomial var7 = new IntegerPolynomial(var2 + 1);
      var7.coeffs[0] = 1;
      var7.coeffs[var2] = 1;

      while(true) {
         while(var6.coeffs[0] == 0) {
            for(int var8 = 1; var8 <= var2; ++var8) {
               var6.coeffs[var8 - 1] = var6.coeffs[var8];
               var5.coeffs[var2 + 1 - var8] = var5.coeffs[var2 - var8];
            }

            var6.coeffs[var2] = 0;
            var5.coeffs[0] = 0;
            ++var3;
            if (var6.equalsZero()) {
               return null;
            }
         }

         IntegerPolynomial var11;
         if (var6.equalsOne()) {
            if (var4.coeffs[var2] != 0) {
               return null;
            }

            var11 = new IntegerPolynomial(var2);
            boolean var9 = false;
            var3 %= var2;

            for(int var10 = var2 - 1; var10 >= 0; --var10) {
               int var12 = var10 - var3;
               if (var12 < 0) {
                  var12 += var2;
               }

               var11.coeffs[var12] = var4.coeffs[var10];
            }

            return this.mod2ToModq(var11, var1);
         }

         if (var6.degree() < var7.degree()) {
            var11 = var6;
            var6 = var7;
            var7 = var11;
            var11 = var4;
            var4 = var5;
            var5 = var11;
         }

         var6.add(var7, 2);
         var4.add(var5, 2);
      }
   }

   private IntegerPolynomial mod2ToModq(IntegerPolynomial var1, int var2) {
      if (Util.is64BitJVM() && var2 == 2048) {
         LongPolynomial2 var7 = new LongPolynomial2(this);
         LongPolynomial2 var8 = new LongPolynomial2(var1);

         LongPolynomial2 var6;
         for(int var5 = 2; var5 < var2; var8 = var6) {
            var5 *= 2;
            var6 = (LongPolynomial2)var8.clone();
            var6.mult2And(var5 - 1);
            var8 = var7.mult(var8).mult(var8);
            var6.subAnd(var8, var5 - 1);
         }

         return var8.toIntegerPolynomial();
      } else {
         IntegerPolynomial var4;
         for(int var3 = 2; var3 < var2; var1 = var4) {
            var3 *= 2;
            var4 = new IntegerPolynomial(Arrays.copyOf(var1.coeffs, var1.coeffs.length));
            var4.mult2(var3);
            var1 = this.mult(var1, var3).mult(var1, var3);
            var4.sub(var1, var3);
         }

         return var1;
      }
   }

   public IntegerPolynomial invertF3() {
      int var1 = this.coeffs.length;
      int var2 = 0;
      IntegerPolynomial var3 = new IntegerPolynomial(var1 + 1);
      var3.coeffs[0] = 1;
      IntegerPolynomial var4 = new IntegerPolynomial(var1 + 1);
      IntegerPolynomial var5 = new IntegerPolynomial(var1 + 1);
      var5.coeffs = Arrays.copyOf(this.coeffs, var1 + 1);
      var5.modPositive(3);
      IntegerPolynomial var6 = new IntegerPolynomial(var1 + 1);
      var6.coeffs[0] = -1;
      var6.coeffs[var1] = 1;

      while(true) {
         while(var5.coeffs[0] == 0) {
            for(int var7 = 1; var7 <= var1; ++var7) {
               var5.coeffs[var7 - 1] = var5.coeffs[var7];
               var4.coeffs[var1 + 1 - var7] = var4.coeffs[var1 - var7];
            }

            var5.coeffs[var1] = 0;
            var4.coeffs[0] = 0;
            ++var2;
            if (var5.equalsZero()) {
               return null;
            }
         }

         IntegerPolynomial var10;
         if (var5.equalsAbsOne()) {
            if (var3.coeffs[var1] != 0) {
               return null;
            }

            var10 = new IntegerPolynomial(var1);
            boolean var8 = false;
            var2 %= var1;

            for(int var9 = var1 - 1; var9 >= 0; --var9) {
               int var11 = var9 - var2;
               if (var11 < 0) {
                  var11 += var1;
               }

               var10.coeffs[var11] = var5.coeffs[0] * var3.coeffs[var9];
            }

            var10.ensurePositive(3);
            return var10;
         }

         if (var5.degree() < var6.degree()) {
            var10 = var5;
            var5 = var6;
            var6 = var10;
            var10 = var3;
            var3 = var4;
            var4 = var10;
         }

         if (var5.coeffs[0] == var6.coeffs[0]) {
            var5.sub(var6, 3);
            var3.sub(var4, 3);
         } else {
            var5.add(var6, 3);
            var3.add(var4, 3);
         }
      }
   }

   public Resultant resultant() {
      int var1 = this.coeffs.length;
      LinkedList var2 = new LinkedList();
      BigInteger var3 = null;
      Object var4 = Constants.BIGINT_ONE;
      BigInteger var5 = Constants.BIGINT_ONE;
      int var6 = 1;
      Iterator var7 = BIGINT_PRIMES.iterator();

      while(true) {
         var3 = var7.hasNext() ? (BigInteger)var7.next() : var3.nextProbablePrime();
         ModularResultant var8 = this.resultant(var3.intValue());
         var2.add(var8);
         Object var9 = ((BigInteger)var4).multiply(var3);
         BigIntEuclidean var10 = BigIntEuclidean.calculate(var3, (BigInteger)var4);
         BigInteger var11 = var5;
         var5 = var5.multiply(var10.x.multiply(var3));
         BigInteger var12 = var8.res.multiply(var10.y.multiply((BigInteger)var4));
         var5 = var5.add(var12).mod((BigInteger)var9);
         var4 = var9;
         BigInteger var13 = ((BigInteger)var9).divide(BigInteger.valueOf(2L));
         BigInteger var14 = var13.negate();
         if (var5.compareTo(var13) > 0) {
            var5 = var5.subtract((BigInteger)var9);
         } else if (var5.compareTo(var14) < 0) {
            var5 = var5.add((BigInteger)var9);
         }

         if (var5.equals(var11)) {
            ++var6;
            if (var6 >= 3) {
               while(var2.size() > 1) {
                  var8 = (ModularResultant)var2.removeFirst();
                  var9 = (ModularResultant)var2.removeFirst();
                  ModularResultant var17 = ModularResultant.combineRho(var8, (ModularResultant)var9);
                  var2.addLast(var17);
               }

               BigIntPolynomial var15 = ((ModularResultant)var2.getFirst()).rho;
               BigInteger var16 = ((BigInteger)var9).divide(BigInteger.valueOf(2L));
               BigInteger var18 = var16.negate();
               if (var5.compareTo(var16) > 0) {
                  var5 = var5.subtract((BigInteger)var4);
               }

               if (var5.compareTo(var18) < 0) {
                  var5 = var5.add((BigInteger)var4);
               }

               for(int var19 = 0; var19 < var1; ++var19) {
                  var12 = var15.coeffs[var19];
                  if (var12.compareTo(var16) > 0) {
                     var15.coeffs[var19] = var12.subtract((BigInteger)var4);
                  }

                  if (var12.compareTo(var18) < 0) {
                     var15.coeffs[var19] = var12.add((BigInteger)var4);
                  }
               }

               return new Resultant(var15, var5);
            }
         } else {
            var6 = 1;
         }
      }
   }

   public Resultant resultantMultiThread() {
      int var1 = this.coeffs.length;
      BigInteger var2 = this.squareSum().pow((var1 + 1) / 2);
      var2 = var2.multiply(BigInteger.valueOf(2L).pow((this.degree() + 1) / 2));
      BigInteger var3 = var2.multiply(BigInteger.valueOf(2L));
      BigInteger var4 = BigInteger.valueOf(10000L);
      BigInteger var5 = Constants.BIGINT_ONE;
      LinkedBlockingQueue var6 = new LinkedBlockingQueue();
      Iterator var7 = BIGINT_PRIMES.iterator();

      ExecutorService var8;
      for(var8 = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors()); var5.compareTo(var3) < 0; var5 = var5.multiply(var4)) {
         if (var7.hasNext()) {
            var4 = (BigInteger)var7.next();
         } else {
            var4 = var4.nextProbablePrime();
         }

         Future var9 = var8.submit(new IntegerPolynomial.ModResultantTask(var4.intValue(), (IntegerPolynomial.ModResultantTask)null));
         var6.add(var9);
      }

      ModularResultant var17 = null;

      while(!var6.isEmpty()) {
         try {
            Future var10 = (Future)var6.take();
            Future var11 = (Future)var6.poll();
            if (var11 == null) {
               var17 = (ModularResultant)var10.get();
               break;
            }

            Future var12 = var8.submit(new IntegerPolynomial.CombineTask((ModularResultant)var10.get(), (ModularResultant)var11.get(), (IntegerPolynomial.CombineTask)null));
            var6.add(var12);
         } catch (Exception var16) {
            throw new IllegalStateException(var16.toString());
         }
      }

      var8.shutdown();
      BigInteger var18 = var17.res;
      BigIntPolynomial var19 = var17.rho;
      BigInteger var20 = var5.divide(BigInteger.valueOf(2L));
      BigInteger var13 = var20.negate();
      if (var18.compareTo(var20) > 0) {
         var18 = var18.subtract(var5);
      }

      if (var18.compareTo(var13) < 0) {
         var18 = var18.add(var5);
      }

      for(int var14 = 0; var14 < var1; ++var14) {
         BigInteger var15 = var19.coeffs[var14];
         if (var15.compareTo(var20) > 0) {
            var19.coeffs[var14] = var15.subtract(var5);
         }

         if (var15.compareTo(var13) < 0) {
            var19.coeffs[var14] = var15.add(var5);
         }
      }

      return new Resultant(var19, var18);
   }

   public ModularResultant resultant(int var1) {
      int[] var2 = Arrays.copyOf(this.coeffs, this.coeffs.length + 1);
      IntegerPolynomial var3 = new IntegerPolynomial(var2);
      int var4 = var2.length;
      IntegerPolynomial var5 = new IntegerPolynomial(var4);
      var5.coeffs[0] = -1;
      var5.coeffs[var4 - 1] = 1;
      IntegerPolynomial var6 = new IntegerPolynomial(var3.coeffs);
      IntegerPolynomial var7 = new IntegerPolynomial(var4);
      IntegerPolynomial var8 = new IntegerPolynomial(var4);
      var8.coeffs[0] = 1;
      int var9 = var4 - 1;
      int var10 = var6.degree();
      int var11 = var9;
      boolean var12 = false;
      int var13 = 1;

      int var16;
      while(var10 > 0) {
         var16 = Util.invert(var6.coeffs[var10], var1);
         var16 = var16 * var5.coeffs[var9] % var1;
         var5.multShiftSub(var6, var16, var9 - var10, var1);
         var7.multShiftSub(var8, var16, var9 - var10, var1);
         var9 = var5.degree();
         if (var9 < var10) {
            var13 *= Util.pow(var6.coeffs[var10], var11 - var9, var1);
            var13 %= var1;
            if (var11 % 2 == 1 && var10 % 2 == 1) {
               var13 = -var13 % var1;
            }

            IntegerPolynomial var14 = var5;
            var5 = var6;
            var6 = var14;
            int var15 = var9;
            var9 = var10;
            var14 = var7;
            var7 = var8;
            var8 = var14;
            var11 = var10;
            var10 = var15;
         }
      }

      var13 *= Util.pow(var6.coeffs[0], var9, var1);
      var13 %= var1;
      var16 = Util.invert(var6.coeffs[0], var1);
      var8.mult(var16);
      var8.mod(var1);
      var8.mult(var13);
      var8.mod(var1);
      var8.coeffs = Arrays.copyOf(var8.coeffs, var8.coeffs.length - 1);
      return new ModularResultant(new BigIntPolynomial(var8), BigInteger.valueOf((long)var13), BigInteger.valueOf((long)var1));
   }

   private void multShiftSub(IntegerPolynomial var1, int var2, int var3, int var4) {
      int var5 = this.coeffs.length;

      for(int var6 = var3; var6 < var5; ++var6) {
         this.coeffs[var6] = (this.coeffs[var6] - var1.coeffs[var6 - var3] * var2) % var4;
      }

   }

   private BigInteger squareSum() {
      BigInteger var1 = Constants.BIGINT_ZERO;

      for(int var2 = 0; var2 < this.coeffs.length; ++var2) {
         var1 = var1.add(BigInteger.valueOf((long)(this.coeffs[var2] * this.coeffs[var2])));
      }

      return var1;
   }

   int degree() {
      int var1;
      for(var1 = this.coeffs.length - 1; var1 > 0 && this.coeffs[var1] == 0; --var1) {
         ;
      }

      return var1;
   }

   public void add(IntegerPolynomial var1, int var2) {
      this.add(var1);
      this.mod(var2);
   }

   public void add(IntegerPolynomial var1) {
      if (var1.coeffs.length > this.coeffs.length) {
         this.coeffs = Arrays.copyOf(this.coeffs, var1.coeffs.length);
      }

      for(int var2 = 0; var2 < var1.coeffs.length; ++var2) {
         this.coeffs[var2] += var1.coeffs[var2];
      }

   }

   public void sub(IntegerPolynomial var1, int var2) {
      this.sub(var1);
      this.mod(var2);
   }

   public void sub(IntegerPolynomial var1) {
      if (var1.coeffs.length > this.coeffs.length) {
         this.coeffs = Arrays.copyOf(this.coeffs, var1.coeffs.length);
      }

      for(int var2 = 0; var2 < var1.coeffs.length; ++var2) {
         this.coeffs[var2] -= var1.coeffs[var2];
      }

   }

   void sub(int var1) {
      for(int var2 = 0; var2 < this.coeffs.length; ++var2) {
         this.coeffs[var2] -= var1;
      }

   }

   public void mult(int var1) {
      for(int var2 = 0; var2 < this.coeffs.length; ++var2) {
         this.coeffs[var2] *= var1;
      }

   }

   private void mult2(int var1) {
      for(int var2 = 0; var2 < this.coeffs.length; ++var2) {
         this.coeffs[var2] *= 2;
         this.coeffs[var2] %= var1;
      }

   }

   public void mult3(int var1) {
      for(int var2 = 0; var2 < this.coeffs.length; ++var2) {
         this.coeffs[var2] *= 3;
         this.coeffs[var2] %= var1;
      }

   }

   public void div(int var1) {
      int var2 = (var1 + 1) / 2;

      for(int var3 = 0; var3 < this.coeffs.length; ++var3) {
         this.coeffs[var3] += this.coeffs[var3] > 0 ? var2 : -var2;
         this.coeffs[var3] /= var1;
      }

   }

   public void mod3() {
      for(int var1 = 0; var1 < this.coeffs.length; ++var1) {
         this.coeffs[var1] %= 3;
         if (this.coeffs[var1] > 1) {
            this.coeffs[var1] -= 3;
         }

         if (this.coeffs[var1] < -1) {
            this.coeffs[var1] += 3;
         }
      }

   }

   public void modPositive(int var1) {
      this.mod(var1);
      this.ensurePositive(var1);
   }

   void modCenter(int var1) {
      this.mod(var1);

      for(int var2 = 0; var2 < this.coeffs.length; ++var2) {
         while(this.coeffs[var2] < var1 / 2) {
            this.coeffs[var2] += var1;
         }

         while(this.coeffs[var2] >= var1 / 2) {
            this.coeffs[var2] -= var1;
         }
      }

   }

   public void mod(int var1) {
      for(int var2 = 0; var2 < this.coeffs.length; ++var2) {
         this.coeffs[var2] %= var1;
      }

   }

   public void ensurePositive(int var1) {
      for(int var2 = 0; var2 < this.coeffs.length; ++var2) {
         while(this.coeffs[var2] < 0) {
            this.coeffs[var2] += var1;
         }
      }

   }

   public long centeredNormSq(int var1) {
      int var2 = this.coeffs.length;
      IntegerPolynomial var3 = (IntegerPolynomial)this.clone();
      var3.shiftGap(var1);
      long var4 = 0L;
      long var6 = 0L;

      for(int var8 = 0; var8 != var3.coeffs.length; ++var8) {
         int var9 = var3.coeffs[var8];
         var4 += (long)var9;
         var6 += (long)(var9 * var9);
      }

      long var10 = var6 - var4 * var4 / (long)var2;
      return var10;
   }

   void shiftGap(int var1) {
      this.modCenter(var1);
      int[] var2 = Arrays.clone(this.coeffs);
      this.sort(var2);
      int var3 = 0;
      int var4 = 0;

      int var5;
      int var6;
      for(var5 = 0; var5 < var2.length - 1; ++var5) {
         var6 = var2[var5 + 1] - var2[var5];
         if (var6 > var3) {
            var3 = var6;
            var4 = var2[var5];
         }
      }

      var5 = var2[0];
      var6 = var2[var2.length - 1];
      int var7 = var1 - var6 + var5;
      int var8;
      if (var7 > var3) {
         var8 = (var6 + var5) / 2;
      } else {
         var8 = var4 + var3 / 2 + var1 / 2;
      }

      this.sub(var8);
   }

   private void sort(int[] var1) {
      boolean var2 = true;

      while(var2) {
         var2 = false;

         for(int var3 = 0; var3 != var1.length - 1; ++var3) {
            if (var1[var3] > var1[var3 + 1]) {
               int var4 = var1[var3];
               var1[var3] = var1[var3 + 1];
               var1[var3 + 1] = var4;
               var2 = true;
            }
         }
      }

   }

   public void center0(int var1) {
      for(int var2 = 0; var2 < this.coeffs.length; ++var2) {
         while(this.coeffs[var2] < -var1 / 2) {
            this.coeffs[var2] += var1;
         }

         while(this.coeffs[var2] > var1 / 2) {
            this.coeffs[var2] -= var1;
         }
      }

   }

   public int sumCoeffs() {
      int var1 = 0;

      for(int var2 = 0; var2 < this.coeffs.length; ++var2) {
         var1 += this.coeffs[var2];
      }

      return var1;
   }

   private boolean equalsZero() {
      for(int var1 = 0; var1 < this.coeffs.length; ++var1) {
         if (this.coeffs[var1] != 0) {
            return false;
         }
      }

      return true;
   }

   public boolean equalsOne() {
      for(int var1 = 1; var1 < this.coeffs.length; ++var1) {
         if (this.coeffs[var1] != 0) {
            return false;
         }
      }

      return this.coeffs[0] == 1;
   }

   private boolean equalsAbsOne() {
      for(int var1 = 1; var1 < this.coeffs.length; ++var1) {
         if (this.coeffs[var1] != 0) {
            return false;
         }
      }

      return Math.abs(this.coeffs[0]) == 1;
   }

   public int count(int var1) {
      int var2 = 0;

      for(int var3 = 0; var3 != this.coeffs.length; ++var3) {
         if (this.coeffs[var3] == var1) {
            ++var2;
         }
      }

      return var2;
   }

   public void rotate1() {
      int var1 = this.coeffs[this.coeffs.length - 1];

      for(int var2 = this.coeffs.length - 1; var2 > 0; --var2) {
         this.coeffs[var2] = this.coeffs[var2 - 1];
      }

      this.coeffs[0] = var1;
   }

   public void clear() {
      for(int var1 = 0; var1 < this.coeffs.length; ++var1) {
         this.coeffs[var1] = 0;
      }

   }

   public IntegerPolynomial toIntegerPolynomial() {
      return (IntegerPolynomial)this.clone();
   }

   public Object clone() {
      return new IntegerPolynomial((int[])this.coeffs.clone());
   }

   public boolean equals(Object var1) {
      return var1 instanceof IntegerPolynomial ? Arrays.areEqual(this.coeffs, ((IntegerPolynomial)var1).coeffs) : false;
   }

   private class CombineTask implements Callable<ModularResultant> {
      private ModularResultant modRes1;
      private ModularResultant modRes2;

      private CombineTask(ModularResultant var2, ModularResultant var3) {
         this.modRes1 = var2;
         this.modRes2 = var3;
      }

      public ModularResultant call() {
         return ModularResultant.combineRho(this.modRes1, this.modRes2);
      }

      // $FF: synthetic method
      CombineTask(ModularResultant var2, ModularResultant var3, IntegerPolynomial.CombineTask var4) {
         this(var2, var3);
      }
   }

   private class ModResultantTask implements Callable<ModularResultant> {
      private int modulus;

      private ModResultantTask(int var2) {
         this.modulus = var2;
      }

      public ModularResultant call() {
         return IntegerPolynomial.this.resultant(this.modulus);
      }

      // $FF: synthetic method
      ModResultantTask(int var2, IntegerPolynomial.ModResultantTask var3) {
         this(var2);
      }
   }
}
