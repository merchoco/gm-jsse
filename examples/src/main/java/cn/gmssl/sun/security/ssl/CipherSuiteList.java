package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import javax.net.ssl.SSLException;

final class CipherSuiteList {
   private final Collection<CipherSuite> cipherSuites;
   private String[] suiteNames;
   private volatile Boolean containsEC;
   // $FF: synthetic field
   private static int[] $SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange;

   CipherSuiteList(Collection<CipherSuite> var1) {
      this.cipherSuites = var1;
   }

   CipherSuiteList(CipherSuite var1) {
      this.cipherSuites = new ArrayList(1);
      this.cipherSuites.add(var1);
   }

   CipherSuiteList(String[] var1) {
      if (var1 == null) {
         throw new IllegalArgumentException("CipherSuites may not be null");
      } else {
         this.cipherSuites = new ArrayList(var1.length);
         boolean var2 = false;

         for(int var3 = 0; var3 < var1.length; ++var3) {
            String var4 = var1[var3];
            CipherSuite var5 = CipherSuite.valueOf(var4);
            if (!var5.isAvailable()) {
               if (!var2) {
                  clearAvailableCache();
                  var2 = true;
               }

               if (!var5.isAvailable()) {
                  throw new IllegalArgumentException("Cannot support " + var4 + " with currently installed providers");
               }
            }

            this.cipherSuites.add(var5);
         }

      }
   }

   CipherSuiteList(HandshakeInStream var1) throws IOException {
      byte[] var2 = var1.getBytes16();
      if ((var2.length & 1) != 0) {
         throw new SSLException("Invalid ClientHello message");
      } else {
         this.cipherSuites = new ArrayList(var2.length >> 1);

         for(int var3 = 0; var3 < var2.length; var3 += 2) {
            this.cipherSuites.add(CipherSuite.valueOf(var2[var3], var2[var3 + 1]));
         }

      }
   }

   boolean contains(CipherSuite var1) {
      return this.cipherSuites.contains(var1);
   }

   boolean containsEC() {
      if (this.containsEC == null) {
         Iterator var2 = this.cipherSuites.iterator();

         while(var2.hasNext()) {
            CipherSuite var1 = (CipherSuite)var2.next();
            switch($SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange()[var1.keyExchange.ordinal()]) {
            case 9:
            case 10:
            case 11:
            case 12:
            case 13:
               this.containsEC = true;
               return true;
            }
         }

         this.containsEC = false;
      }

      return this.containsEC;
   }

   Iterator<CipherSuite> iterator() {
      return this.cipherSuites.iterator();
   }

   Collection<CipherSuite> collection() {
      return this.cipherSuites;
   }

   int size() {
      return this.cipherSuites.size();
   }

   synchronized String[] toStringArray() {
      if (this.suiteNames == null) {
         this.suiteNames = new String[this.cipherSuites.size()];
         int var1 = 0;

         CipherSuite var2;
         for(Iterator var3 = this.cipherSuites.iterator(); var3.hasNext(); this.suiteNames[var1++] = var2.name) {
            var2 = (CipherSuite)var3.next();
         }
      }

      return (String[])this.suiteNames.clone();
   }

   public String toString() {
      return this.cipherSuites.toString();
   }

   void send(HandshakeOutStream var1) throws IOException {
      byte[] var2 = new byte[this.cipherSuites.size() * 2];
      int var3 = 0;

      for(Iterator var5 = this.cipherSuites.iterator(); var5.hasNext(); var3 += 2) {
         CipherSuite var4 = (CipherSuite)var5.next();
         var2[var3] = (byte)(var4.id >> 8);
         var2[var3 + 1] = (byte)var4.id;
      }

      var1.putBytes16(var2);
   }

   static synchronized void clearAvailableCache() {
      CipherSuite.BulkCipher.clearAvailableCache();
      JsseJce.clearEcAvailable();
   }

   // $FF: synthetic method
   static int[] $SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange() {
      int[] var10000 = $SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange;
      if ($SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange != null) {
         return var10000;
      } else {
         int[] var0 = new int[CipherSuite.KeyExchange.values().length];

         try {
            var0[CipherSuite.KeyExchange.K_DHE_DSS.ordinal()] = 6;
         } catch (NoSuchFieldError var18) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_DHE_RSA.ordinal()] = 7;
         } catch (NoSuchFieldError var17) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_DH_ANON.ordinal()] = 8;
         } catch (NoSuchFieldError var16) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_DH_DSS.ordinal()] = 5;
         } catch (NoSuchFieldError var15) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_DH_RSA.ordinal()] = 4;
         } catch (NoSuchFieldError var14) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_ECC.ordinal()] = 15;
         } catch (NoSuchFieldError var13) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_ECDHE_ECDSA.ordinal()] = 11;
         } catch (NoSuchFieldError var12) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_ECDHE_RSA.ordinal()] = 12;
         } catch (NoSuchFieldError var11) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_ECDH_ANON.ordinal()] = 13;
         } catch (NoSuchFieldError var10) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_ECDH_ECDSA.ordinal()] = 9;
         } catch (NoSuchFieldError var9) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_ECDH_RSA.ordinal()] = 10;
         } catch (NoSuchFieldError var8) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_KRB5.ordinal()] = 16;
         } catch (NoSuchFieldError var7) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_KRB5_EXPORT.ordinal()] = 17;
         } catch (NoSuchFieldError var6) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_NULL.ordinal()] = 1;
         } catch (NoSuchFieldError var5) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_RSA.ordinal()] = 2;
         } catch (NoSuchFieldError var4) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_RSA_EXPORT.ordinal()] = 3;
         } catch (NoSuchFieldError var3) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_SCSV.ordinal()] = 18;
         } catch (NoSuchFieldError var2) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_SM2_SM2.ordinal()] = 14;
         } catch (NoSuchFieldError var1) {
            ;
         }

         $SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange = var0;
         return var0;
      }
   }
}
