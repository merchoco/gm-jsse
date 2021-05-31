package cn.gmssl.sun.security.ssl;

import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;

class EngineArgs {
   ByteBuffer netData;
   ByteBuffer[] appData;
   private int offset;
   private int len;
   private int netPos;
   private int netLim;
   private int[] appPoss;
   private int[] appLims;
   private int appRemaining = 0;
   private boolean wrapMethod;

   EngineArgs(ByteBuffer[] var1, int var2, int var3, ByteBuffer var4) {
      this.wrapMethod = true;
      this.init(var4, var1, var2, var3);
   }

   EngineArgs(ByteBuffer var1, ByteBuffer[] var2, int var3, int var4) {
      this.wrapMethod = false;
      this.init(var1, var2, var3, var4);
   }

   private void init(ByteBuffer var1, ByteBuffer[] var2, int var3, int var4) {
      if (var1 != null && var2 != null) {
         if (var3 >= 0 && var4 >= 0 && var3 <= var2.length - var4) {
            if (this.wrapMethod && var1.isReadOnly()) {
               throw new ReadOnlyBufferException();
            } else {
               this.netPos = var1.position();
               this.netLim = var1.limit();
               this.appPoss = new int[var2.length];
               this.appLims = new int[var2.length];

               for(int var5 = var3; var5 < var3 + var4; ++var5) {
                  if (var2[var5] == null) {
                     throw new IllegalArgumentException("appData[" + var5 + "] == null");
                  }

                  if (!this.wrapMethod && var2[var5].isReadOnly()) {
                     throw new ReadOnlyBufferException();
                  }

                  this.appRemaining += var2[var5].remaining();
                  this.appPoss[var5] = var2[var5].position();
                  this.appLims[var5] = var2[var5].limit();
               }

               this.netData = var1;
               this.appData = var2;
               this.offset = var3;
               this.len = var4;
            }
         } else {
            throw new IndexOutOfBoundsException();
         }
      } else {
         throw new IllegalArgumentException("src/dst is null");
      }
   }

   void gather(int var1) {
      for(int var2 = this.offset; var2 < this.offset + this.len && var1 > 0; ++var2) {
         int var3 = Math.min(this.appData[var2].remaining(), var1);
         this.appData[var2].limit(this.appData[var2].position() + var3);
         this.netData.put(this.appData[var2]);
         var1 -= var3;
      }

   }

   void scatter(ByteBuffer var1) {
      int var2 = var1.remaining();

      for(int var3 = this.offset; var3 < this.offset + this.len && var2 > 0; ++var3) {
         int var4 = Math.min(this.appData[var3].remaining(), var2);
         var1.limit(var1.position() + var4);
         this.appData[var3].put(var1);
         var2 -= var4;
      }

      assert var1.remaining() == 0;

   }

   int getAppRemaining() {
      return this.appRemaining;
   }

   int deltaNet() {
      return this.netData.position() - this.netPos;
   }

   int deltaApp() {
      int var1 = 0;

      for(int var2 = this.offset; var2 < this.offset + this.len; ++var2) {
         var1 += this.appData[var2].position() - this.appPoss[var2];
      }

      return var1;
   }

   void resetPos() {
      this.netData.position(this.netPos);

      for(int var1 = this.offset; var1 < this.offset + this.len; ++var1) {
         this.appData[var1].position(this.appPoss[var1]);
      }

   }

   void resetLim() {
      this.netData.limit(this.netLim);

      for(int var1 = this.offset; var1 < this.offset + this.len; ++var1) {
         this.appData[var1].limit(this.appLims[var1]);
      }

   }
}
