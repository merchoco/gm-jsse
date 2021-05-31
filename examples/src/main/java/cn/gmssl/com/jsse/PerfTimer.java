package cn.gmssl.com.jsse;

public class PerfTimer {
   long start = 0L;
   private long accumulation = 0L;
   private String name = null;

   public PerfTimer(String var1) {
      this.name = var1;
   }

   public void resume() {
      this.start = System.currentTimeMillis();
   }

   public long pause() {
      long var1 = System.currentTimeMillis() - this.start;
      this.accumulation += var1;
      this.start = 0L;
      return var1;
   }

   public long getConsume() {
      return this.accumulation;
   }

   public void reset() {
      this.accumulation = 0L;
   }

   public void printConsume() {
      System.out.println(this.name + " consume " + this.accumulation + " ms");
   }
}
