package cn.gmssl.jce.provider;

import java.text.SimpleDateFormat;
import java.util.Date;

public final class GMFree {
   public static final String EXPIRE = "2021-12-30 23:00:00";

   public static void init() {
      System.out.println("GMJCE provider by www.gmssl.cn. Test Only!!!");
      System.err.println("GMJCE provider by www.gmssl.cn. Test Only!!!");

      try {
         SimpleDateFormat var0 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
         Date var1 = var0.parse("2021-12-30 23:00:00");
         Date var2 = new Date();
         if (var2.after(var1)) {
            System.out.println("GMJCE provider expired. Please update new version!!!");
            System.err.println("GMJCE provider expired. Please update new version!!!");
            System.exit(0);
         }
      } catch (Exception var3) {
         ;
      }

   }
}
