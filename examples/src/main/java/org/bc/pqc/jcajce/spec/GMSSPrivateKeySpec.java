package org.bc.pqc.jcajce.spec;

import java.security.spec.KeySpec;
import java.util.Vector;
import org.bc.pqc.crypto.gmss.GMSSLeaf;
import org.bc.pqc.crypto.gmss.GMSSParameters;
import org.bc.pqc.crypto.gmss.GMSSRootCalc;
import org.bc.pqc.crypto.gmss.GMSSRootSig;
import org.bc.pqc.crypto.gmss.Treehash;
import org.bc.util.Arrays;

public class GMSSPrivateKeySpec implements KeySpec {
   private int[] index;
   private byte[][] currentSeed;
   private byte[][] nextNextSeed;
   private byte[][][] currentAuthPath;
   private byte[][][] nextAuthPath;
   private Treehash[][] currentTreehash;
   private Treehash[][] nextTreehash;
   private Vector[] currentStack;
   private Vector[] nextStack;
   private Vector[][] currentRetain;
   private Vector[][] nextRetain;
   private byte[][][] keep;
   private GMSSLeaf[] nextNextLeaf;
   private GMSSLeaf[] upperLeaf;
   private GMSSLeaf[] upperTreehashLeaf;
   private int[] minTreehash;
   private GMSSParameters gmssPS;
   private byte[][] nextRoot;
   private GMSSRootCalc[] nextNextRoot;
   private byte[][] currentRootSig;
   private GMSSRootSig[] nextRootSig;

   public GMSSPrivateKeySpec(int[] var1, byte[][] var2, byte[][] var3, byte[][][] var4, byte[][][] var5, Treehash[][] var6, Treehash[][] var7, Vector[] var8, Vector[] var9, Vector[][] var10, Vector[][] var11, byte[][][] var12, GMSSLeaf[] var13, GMSSLeaf[] var14, GMSSLeaf[] var15, int[] var16, byte[][] var17, GMSSRootCalc[] var18, byte[][] var19, GMSSRootSig[] var20, GMSSParameters var21) {
      this.index = var1;
      this.currentSeed = var2;
      this.nextNextSeed = var3;
      this.currentAuthPath = var4;
      this.nextAuthPath = var5;
      this.currentTreehash = var6;
      this.nextTreehash = var7;
      this.currentStack = var8;
      this.nextStack = var9;
      this.currentRetain = var10;
      this.nextRetain = var11;
      this.keep = var12;
      this.nextNextLeaf = var13;
      this.upperLeaf = var14;
      this.upperTreehashLeaf = var15;
      this.minTreehash = var16;
      this.nextRoot = var17;
      this.nextNextRoot = var18;
      this.currentRootSig = var19;
      this.nextRootSig = var20;
      this.gmssPS = var21;
   }

   public int[] getIndex() {
      return Arrays.clone(this.index);
   }

   public byte[][] getCurrentSeed() {
      return clone(this.currentSeed);
   }

   public byte[][] getNextNextSeed() {
      return clone(this.nextNextSeed);
   }

   public byte[][][] getCurrentAuthPath() {
      return clone(this.currentAuthPath);
   }

   public byte[][][] getNextAuthPath() {
      return clone(this.nextAuthPath);
   }

   public Treehash[][] getCurrentTreehash() {
      return clone(this.currentTreehash);
   }

   public Treehash[][] getNextTreehash() {
      return clone(this.nextTreehash);
   }

   public byte[][][] getKeep() {
      return clone(this.keep);
   }

   public Vector[] getCurrentStack() {
      return clone(this.currentStack);
   }

   public Vector[] getNextStack() {
      return clone(this.nextStack);
   }

   public Vector[][] getCurrentRetain() {
      return clone(this.currentRetain);
   }

   public Vector[][] getNextRetain() {
      return clone(this.nextRetain);
   }

   public GMSSLeaf[] getNextNextLeaf() {
      return clone(this.nextNextLeaf);
   }

   public GMSSLeaf[] getUpperLeaf() {
      return clone(this.upperLeaf);
   }

   public GMSSLeaf[] getUpperTreehashLeaf() {
      return clone(this.upperTreehashLeaf);
   }

   public int[] getMinTreehash() {
      return Arrays.clone(this.minTreehash);
   }

   public GMSSRootSig[] getNextRootSig() {
      return clone(this.nextRootSig);
   }

   public GMSSParameters getGmssPS() {
      return this.gmssPS;
   }

   public byte[][] getNextRoot() {
      return clone(this.nextRoot);
   }

   public GMSSRootCalc[] getNextNextRoot() {
      return clone(this.nextNextRoot);
   }

   public byte[][] getCurrentRootSig() {
      return clone(this.currentRootSig);
   }

   private static GMSSLeaf[] clone(GMSSLeaf[] var0) {
      if (var0 == null) {
         return null;
      } else {
         GMSSLeaf[] var1 = new GMSSLeaf[var0.length];
         System.arraycopy(var0, 0, var1, 0, var0.length);
         return var1;
      }
   }

   private static GMSSRootCalc[] clone(GMSSRootCalc[] var0) {
      if (var0 == null) {
         return null;
      } else {
         GMSSRootCalc[] var1 = new GMSSRootCalc[var0.length];
         System.arraycopy(var0, 0, var1, 0, var0.length);
         return var1;
      }
   }

   private static GMSSRootSig[] clone(GMSSRootSig[] var0) {
      if (var0 == null) {
         return null;
      } else {
         GMSSRootSig[] var1 = new GMSSRootSig[var0.length];
         System.arraycopy(var0, 0, var1, 0, var0.length);
         return var1;
      }
   }

   private static byte[][] clone(byte[][] var0) {
      if (var0 == null) {
         return null;
      } else {
         byte[][] var1 = new byte[var0.length][];

         for(int var2 = 0; var2 != var0.length; ++var2) {
            var1[var2] = Arrays.clone(var0[var2]);
         }

         return var1;
      }
   }

   private static byte[][][] clone(byte[][][] var0) {
      if (var0 == null) {
         return null;
      } else {
         byte[][][] var1 = new byte[var0.length][][];

         for(int var2 = 0; var2 != var0.length; ++var2) {
            var1[var2] = clone(var0[var2]);
         }

         return var1;
      }
   }

   private static Treehash[] clone(Treehash[] var0) {
      if (var0 == null) {
         return null;
      } else {
         Treehash[] var1 = new Treehash[var0.length];
         System.arraycopy(var0, 0, var1, 0, var0.length);
         return var1;
      }
   }

   private static Treehash[][] clone(Treehash[][] var0) {
      if (var0 == null) {
         return null;
      } else {
         Treehash[][] var1 = new Treehash[var0.length][];

         for(int var2 = 0; var2 != var0.length; ++var2) {
            var1[var2] = clone(var0[var2]);
         }

         return var1;
      }
   }

   private static Vector[] clone(Vector[] var0) {
      if (var0 == null) {
         return null;
      } else {
         Vector[] var1 = new Vector[var0.length];

         for(int var2 = 0; var2 != var0.length; ++var2) {
            var1[var2] = new Vector(var0[var2]);
         }

         return var1;
      }
   }

   private static Vector[][] clone(Vector[][] var0) {
      if (var0 == null) {
         return null;
      } else {
         Vector[][] var1 = new Vector[var0.length][];

         for(int var2 = 0; var2 != var0.length; ++var2) {
            var1[var2] = clone(var0[var2]);
         }

         return var1;
      }
   }
}
