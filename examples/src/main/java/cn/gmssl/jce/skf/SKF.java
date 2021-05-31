package cn.gmssl.jce.skf;

import cn.gmssl.jce.provider.GMConf;
import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class SKF implements ICryptoProvider {
   private static boolean logined = false;
   private int err = 0;

   static {
      System.loadLibrary("skf4gmssl");
   }

   private static native int login(byte[] var0, byte[] var1);

   private static native byte[] getCrt(int var0);

   private static native byte[] sign(byte[] var0, int var1, int var2);

   public boolean login(String var1, String var2) {
      if (!logined) {
         Class var3 = SKF.class;
         synchronized(SKF.class) {
            if (!logined) {
               this.err = login(var1.getBytes(), var2.getBytes());
               if (GMConf.skfDebug) {
                  System.out.println("SKF: login=" + this.err);
               }

               if (this.err == 0) {
                  logined = true;
               }
            }
         }
      }

      return logined;
   }

   public int getError() {
      return this.err;
   }

   public X509Certificate getCert(int var1) throws Exception {
      if (GMConf.skfDebug) {
         System.out.println("getCert sig=" + var1 + ",logined=" + logined);
      }

      if (!logined) {
         return null;
      } else {
         Object var2 = null;

         byte[] var8;
         try {
            Class var3 = SKF.class;
            synchronized(SKF.class) {
               var8 = getCrt(var1);
               if (GMConf.skfDebug) {
                  System.out.println("SKF: sig=" + var1 + ",getCrt=" + var8);
               }
            }
         } catch (Exception var7) {
            var7.printStackTrace();
            throw var7;
         }

         CertificateFactory var9 = CertificateFactory.getInstance("X509");
         ByteArrayInputStream var4 = new ByteArrayInputStream(var8);
         X509Certificate var5 = (X509Certificate)var9.generateCertificate(var4);
         return var5;
      }
   }

   public PrivateKey getPrivateKey(int var1) {
      if (GMConf.skfDebug) {
         System.out.println("getPrivateKey sig=" + var1 + ",logined=" + logined);
      }

      if (!logined) {
         return null;
      } else {
         SKF_PrivateKey var2 = new SKF_PrivateKey(this, var1);
         return var2;
      }
   }

   public byte[] doSign(byte[] var1, int var2, int var3) throws Exception {
      if (GMConf.skfDebug) {
         System.out.println("doSign...offset=" + var2 + ",length=" + var3 + ",logined=" + logined);
      }

      if (!logined) {
         return null;
      } else {
         try {
            Object var4 = null;
            Class var5 = SKF.class;
            synchronized(SKF.class) {
               byte[] var8 = sign(var1, var2, var3);
               if (GMConf.skfDebug) {
                  System.out.println("SKF: sign=" + var8 + "," + var8[0] + "," + var8[32]);
               }

               return var8;
            }
         } catch (Exception var7) {
            var7.printStackTrace();
            throw var7;
         }
      }
   }
}
