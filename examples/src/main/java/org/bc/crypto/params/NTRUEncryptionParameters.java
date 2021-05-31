package org.bc.crypto.params;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import org.bc.crypto.Digest;
import org.bc.crypto.digests.SHA256Digest;
import org.bc.crypto.digests.SHA512Digest;

public class NTRUEncryptionParameters implements Cloneable {
   public int N;
   public int q;
   public int df;
   public int df1;
   public int df2;
   public int df3;
   public int dr;
   public int dr1;
   public int dr2;
   public int dr3;
   public int dg;
   int llen;
   public int maxMsgLenBytes;
   public int db;
   public int bufferLenBits;
   int bufferLenTrits;
   public int dm0;
   public int pkLen;
   public int c;
   public int minCallsR;
   public int minCallsMask;
   public boolean hashSeed;
   public byte[] oid;
   public boolean sparse;
   public boolean fastFp;
   public int polyType;
   public Digest hashAlg;

   public NTRUEncryptionParameters(int var1, int var2, int var3, int var4, int var5, int var6, int var7, int var8, boolean var9, byte[] var10, boolean var11, boolean var12, Digest var13) {
      this.N = var1;
      this.q = var2;
      this.df = var3;
      this.db = var5;
      this.dm0 = var4;
      this.c = var6;
      this.minCallsR = var7;
      this.minCallsMask = var8;
      this.hashSeed = var9;
      this.oid = var10;
      this.sparse = var11;
      this.fastFp = var12;
      this.polyType = 0;
      this.hashAlg = var13;
      this.init();
   }

   public NTRUEncryptionParameters(int var1, int var2, int var3, int var4, int var5, int var6, int var7, int var8, int var9, int var10, boolean var11, byte[] var12, boolean var13, boolean var14, Digest var15) {
      this.N = var1;
      this.q = var2;
      this.df1 = var3;
      this.df2 = var4;
      this.df3 = var5;
      this.db = var7;
      this.dm0 = var6;
      this.c = var8;
      this.minCallsR = var9;
      this.minCallsMask = var10;
      this.hashSeed = var11;
      this.oid = var12;
      this.sparse = var13;
      this.fastFp = var14;
      this.polyType = 1;
      this.hashAlg = var15;
      this.init();
   }

   private void init() {
      this.dr = this.df;
      this.dr1 = this.df1;
      this.dr2 = this.df2;
      this.dr3 = this.df3;
      this.dg = this.N / 3;
      this.llen = 1;
      this.maxMsgLenBytes = this.N * 3 / 2 / 8 - this.llen - this.db / 8 - 1;
      this.bufferLenBits = (this.N * 3 / 2 + 7) / 8 * 8 + 1;
      this.bufferLenTrits = this.N - 1;
      this.pkLen = this.db;
   }

   public NTRUEncryptionParameters(InputStream var1) throws IOException {
      DataInputStream var2 = new DataInputStream(var1);
      this.N = var2.readInt();
      this.q = var2.readInt();
      this.df = var2.readInt();
      this.df1 = var2.readInt();
      this.df2 = var2.readInt();
      this.df3 = var2.readInt();
      this.db = var2.readInt();
      this.dm0 = var2.readInt();
      this.c = var2.readInt();
      this.minCallsR = var2.readInt();
      this.minCallsMask = var2.readInt();
      this.hashSeed = var2.readBoolean();
      this.oid = new byte[3];
      var2.read(this.oid);
      this.sparse = var2.readBoolean();
      this.fastFp = var2.readBoolean();
      this.polyType = var2.read();
      String var3 = var2.readUTF();
      if ("SHA-512".equals(var3)) {
         this.hashAlg = new SHA512Digest();
      } else if ("SHA-256".equals(var3)) {
         this.hashAlg = new SHA256Digest();
      }

      this.init();
   }

   public NTRUEncryptionParameters clone() {
      return this.polyType == 0 ? new NTRUEncryptionParameters(this.N, this.q, this.df, this.dm0, this.db, this.c, this.minCallsR, this.minCallsMask, this.hashSeed, this.oid, this.sparse, this.fastFp, this.hashAlg) : new NTRUEncryptionParameters(this.N, this.q, this.df1, this.df2, this.df3, this.dm0, this.db, this.c, this.minCallsR, this.minCallsMask, this.hashSeed, this.oid, this.sparse, this.fastFp, this.hashAlg);
   }

   public int getMaxMessageLength() {
      return this.maxMsgLenBytes;
   }

   public void writeTo(OutputStream var1) throws IOException {
      DataOutputStream var2 = new DataOutputStream(var1);
      var2.writeInt(this.N);
      var2.writeInt(this.q);
      var2.writeInt(this.df);
      var2.writeInt(this.df1);
      var2.writeInt(this.df2);
      var2.writeInt(this.df3);
      var2.writeInt(this.db);
      var2.writeInt(this.dm0);
      var2.writeInt(this.c);
      var2.writeInt(this.minCallsR);
      var2.writeInt(this.minCallsMask);
      var2.writeBoolean(this.hashSeed);
      var2.write(this.oid);
      var2.writeBoolean(this.sparse);
      var2.writeBoolean(this.fastFp);
      var2.write(this.polyType);
      var2.writeUTF(this.hashAlg.getAlgorithmName());
   }

   public int hashCode() {
      boolean var1 = true;
      byte var2 = 1;
      int var3 = 31 * var2 + this.N;
      var3 = 31 * var3 + this.bufferLenBits;
      var3 = 31 * var3 + this.bufferLenTrits;
      var3 = 31 * var3 + this.c;
      var3 = 31 * var3 + this.db;
      var3 = 31 * var3 + this.df;
      var3 = 31 * var3 + this.df1;
      var3 = 31 * var3 + this.df2;
      var3 = 31 * var3 + this.df3;
      var3 = 31 * var3 + this.dg;
      var3 = 31 * var3 + this.dm0;
      var3 = 31 * var3 + this.dr;
      var3 = 31 * var3 + this.dr1;
      var3 = 31 * var3 + this.dr2;
      var3 = 31 * var3 + this.dr3;
      var3 = 31 * var3 + (this.fastFp ? 1231 : 1237);
      var3 = 31 * var3 + (this.hashAlg == null ? 0 : this.hashAlg.getAlgorithmName().hashCode());
      var3 = 31 * var3 + (this.hashSeed ? 1231 : 1237);
      var3 = 31 * var3 + this.llen;
      var3 = 31 * var3 + this.maxMsgLenBytes;
      var3 = 31 * var3 + this.minCallsMask;
      var3 = 31 * var3 + this.minCallsR;
      var3 = 31 * var3 + Arrays.hashCode(this.oid);
      var3 = 31 * var3 + this.pkLen;
      var3 = 31 * var3 + this.polyType;
      var3 = 31 * var3 + this.q;
      var3 = 31 * var3 + (this.sparse ? 1231 : 1237);
      return var3;
   }

   public boolean equals(Object var1) {
      if (this == var1) {
         return true;
      } else if (var1 == null) {
         return false;
      } else if (this.getClass() != var1.getClass()) {
         return false;
      } else {
         NTRUEncryptionParameters var2 = (NTRUEncryptionParameters)var1;
         if (this.N != var2.N) {
            return false;
         } else if (this.bufferLenBits != var2.bufferLenBits) {
            return false;
         } else if (this.bufferLenTrits != var2.bufferLenTrits) {
            return false;
         } else if (this.c != var2.c) {
            return false;
         } else if (this.db != var2.db) {
            return false;
         } else if (this.df != var2.df) {
            return false;
         } else if (this.df1 != var2.df1) {
            return false;
         } else if (this.df2 != var2.df2) {
            return false;
         } else if (this.df3 != var2.df3) {
            return false;
         } else if (this.dg != var2.dg) {
            return false;
         } else if (this.dm0 != var2.dm0) {
            return false;
         } else if (this.dr != var2.dr) {
            return false;
         } else if (this.dr1 != var2.dr1) {
            return false;
         } else if (this.dr2 != var2.dr2) {
            return false;
         } else if (this.dr3 != var2.dr3) {
            return false;
         } else if (this.fastFp != var2.fastFp) {
            return false;
         } else {
            if (this.hashAlg == null) {
               if (var2.hashAlg != null) {
                  return false;
               }
            } else if (!this.hashAlg.getAlgorithmName().equals(var2.hashAlg.getAlgorithmName())) {
               return false;
            }

            if (this.hashSeed != var2.hashSeed) {
               return false;
            } else if (this.llen != var2.llen) {
               return false;
            } else if (this.maxMsgLenBytes != var2.maxMsgLenBytes) {
               return false;
            } else if (this.minCallsMask != var2.minCallsMask) {
               return false;
            } else if (this.minCallsR != var2.minCallsR) {
               return false;
            } else if (!Arrays.equals(this.oid, var2.oid)) {
               return false;
            } else if (this.pkLen != var2.pkLen) {
               return false;
            } else if (this.polyType != var2.polyType) {
               return false;
            } else if (this.q != var2.q) {
               return false;
            } else {
               return this.sparse == var2.sparse;
            }
         }
      }
   }

   public String toString() {
      StringBuilder var1 = new StringBuilder("EncryptionParameters(N=" + this.N + " q=" + this.q);
      if (this.polyType == 0) {
         var1.append(" polyType=SIMPLE df=" + this.df);
      } else {
         var1.append(" polyType=PRODUCT df1=" + this.df1 + " df2=" + this.df2 + " df3=" + this.df3);
      }

      var1.append(" dm0=" + this.dm0 + " db=" + this.db + " c=" + this.c + " minCallsR=" + this.minCallsR + " minCallsMask=" + this.minCallsMask + " hashSeed=" + this.hashSeed + " hashAlg=" + this.hashAlg + " oid=" + Arrays.toString(this.oid) + " sparse=" + this.sparse + ")");
      return var1.toString();
   }
}
