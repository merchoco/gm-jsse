package org.bc.math.ntru.util;

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import org.bc.math.ntru.euclid.IntEuclidean;
import org.bc.math.ntru.polynomial.DenseTernaryPolynomial;
import org.bc.math.ntru.polynomial.SparseTernaryPolynomial;
import org.bc.math.ntru.polynomial.TernaryPolynomial;
import org.bc.util.Integers;

public class Util {
   private static volatile boolean IS_64_BITNESS_KNOWN;
   private static volatile boolean IS_64_BIT_JVM;

   public static int invert(int var0, int var1) {
      var0 %= var1;
      if (var0 < 0) {
         var0 += var1;
      }

      return IntEuclidean.calculate(var0, var1).x;
   }

   public static int pow(int var0, int var1, int var2) {
      int var3 = 1;

      for(int var4 = 0; var4 < var1; ++var4) {
         var3 = var3 * var0 % var2;
      }

      return var3;
   }

   public static long pow(long var0, int var2, long var3) {
      long var5 = 1L;

      for(int var7 = 0; var7 < var2; ++var7) {
         var5 = var5 * var0 % var3;
      }

      return var5;
   }

   public static TernaryPolynomial generateRandomTernary(int var0, int var1, int var2, boolean var3, SecureRandom var4) {
      return (TernaryPolynomial)(var3 ? SparseTernaryPolynomial.generateRandom(var0, var1, var2, var4) : DenseTernaryPolynomial.generateRandom(var0, var1, var2, var4));
   }

   public static int[] generateRandomTernary(int var0, int var1, int var2, SecureRandom var3) {
      Integer var4 = Integers.valueOf(1);
      Integer var5 = Integers.valueOf(-1);
      Integer var6 = Integers.valueOf(0);
      ArrayList var7 = new ArrayList();

      int var8;
      for(var8 = 0; var8 < var1; ++var8) {
         var7.add(var4);
      }

      for(var8 = 0; var8 < var2; ++var8) {
         var7.add(var5);
      }

      while(var7.size() < var0) {
         var7.add(var6);
      }

      Collections.shuffle(var7, var3);
      int[] var10 = new int[var0];

      for(int var9 = 0; var9 < var0; ++var9) {
         var10[var9] = (Integer)var7.get(var9);
      }

      return var10;
   }

   public static boolean is64BitJVM() {
      if (!IS_64_BITNESS_KNOWN) {
         String var0 = System.getProperty("os.arch");
         String var1 = System.getProperty("sun.arch.data.model");
         IS_64_BIT_JVM = "amd64".equals(var0) || "x86_64".equals(var0) || "ppc64".equals(var0) || "64".equals(var1);
         IS_64_BITNESS_KNOWN = true;
      }

      return IS_64_BIT_JVM;
   }

   public static byte[] readFullLength(InputStream var0, int var1) throws IOException {
      byte[] var2 = new byte[var1];
      if (var0.read(var2) != var2.length) {
         throw new IOException("Not enough bytes to read.");
      } else {
         return var2;
      }
   }
}
