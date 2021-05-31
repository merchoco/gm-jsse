package cn.gmssl.sun.security.ssl;

import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.Key;
import java.util.HashSet;
import java.util.Set;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import sun.security.util.DisabledAlgorithmConstraints;

final class SSLAlgorithmConstraints implements AlgorithmConstraints {
   private static final AlgorithmConstraints tlsDisabledAlgConstraints = new SSLAlgorithmConstraints.TLSDisabledAlgConstraints();
   private static final AlgorithmConstraints x509DisabledAlgConstraints = new SSLAlgorithmConstraints.X509DisabledAlgConstraints();
   private AlgorithmConstraints userAlgConstraints = null;
   private AlgorithmConstraints peerAlgConstraints = null;
   private boolean enabledX509DisabledAlgConstraints = true;

   SSLAlgorithmConstraints(AlgorithmConstraints var1) {
      this.userAlgConstraints = var1;
   }

   SSLAlgorithmConstraints(SSLSocket var1, boolean var2) {
      if (var1 != null) {
         this.userAlgConstraints = var1.getSSLParameters().getAlgorithmConstraints();
      }

      if (!var2) {
         this.enabledX509DisabledAlgConstraints = false;
      }

   }

   SSLAlgorithmConstraints(SSLEngine var1, boolean var2) {
      if (var1 != null) {
         this.userAlgConstraints = var1.getSSLParameters().getAlgorithmConstraints();
      }

      if (!var2) {
         this.enabledX509DisabledAlgConstraints = false;
      }

   }

   SSLAlgorithmConstraints(SSLSocket var1, String[] var2, boolean var3) {
      if (var1 != null) {
         this.userAlgConstraints = var1.getSSLParameters().getAlgorithmConstraints();
         this.peerAlgConstraints = new SSLAlgorithmConstraints.SupportedSignatureAlgorithmConstraints(var2);
      }

      if (!var3) {
         this.enabledX509DisabledAlgConstraints = false;
      }

   }

   SSLAlgorithmConstraints(SSLEngine var1, String[] var2, boolean var3) {
      if (var1 != null) {
         this.userAlgConstraints = var1.getSSLParameters().getAlgorithmConstraints();
         this.peerAlgConstraints = new SSLAlgorithmConstraints.SupportedSignatureAlgorithmConstraints(var2);
      }

      if (!var3) {
         this.enabledX509DisabledAlgConstraints = false;
      }

   }

   public boolean permits(Set<CryptoPrimitive> var1, String var2, AlgorithmParameters var3) {
      boolean var4 = true;
      if (this.peerAlgConstraints != null) {
         var4 = this.peerAlgConstraints.permits(var1, var2, var3);
      }

      if (var4 && this.userAlgConstraints != null) {
         var4 = this.userAlgConstraints.permits(var1, var2, var3);
      }

      if (var4) {
         var4 = tlsDisabledAlgConstraints.permits(var1, var2, var3);
      }

      if (var4 && this.enabledX509DisabledAlgConstraints) {
         var4 = x509DisabledAlgConstraints.permits(var1, var2, var3);
      }

      return var4;
   }

   public boolean permits(Set<CryptoPrimitive> var1, Key var2) {
      boolean var3 = true;
      if (this.peerAlgConstraints != null) {
         var3 = this.peerAlgConstraints.permits(var1, var2);
      }

      if (var3 && this.userAlgConstraints != null) {
         var3 = this.userAlgConstraints.permits(var1, var2);
      }

      if (var3) {
         var3 = tlsDisabledAlgConstraints.permits(var1, var2);
      }

      if (var3 && this.enabledX509DisabledAlgConstraints) {
         var3 = x509DisabledAlgConstraints.permits(var1, var2);
      }

      return var3;
   }

   public boolean permits(Set<CryptoPrimitive> var1, String var2, Key var3, AlgorithmParameters var4) {
      boolean var5 = true;
      if (this.peerAlgConstraints != null) {
         var5 = this.peerAlgConstraints.permits(var1, var2, var3, var4);
      }

      if (var5 && this.userAlgConstraints != null) {
         var5 = this.userAlgConstraints.permits(var1, var2, var3, var4);
      }

      if (var5) {
         var5 = tlsDisabledAlgConstraints.permits(var1, var2, var3, var4);
      }

      if (var5 && this.enabledX509DisabledAlgConstraints) {
         var5 = x509DisabledAlgConstraints.permits(var1, var2, var3, var4);
      }

      return var5;
   }

   private static class BasicDisabledAlgConstraints extends DisabledAlgorithmConstraints {
      // $FF: synthetic field
      private static int[] $SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange;

      BasicDisabledAlgConstraints(String var1) {
         super(var1);
      }

      protected Set<String> decomposes(CipherSuite.KeyExchange var1, boolean var2) {
         HashSet var3 = new HashSet();
         switch($SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange()[var1.ordinal()]) {
         case 1:
            if (!var2) {
               var3.add("NULL");
            }
            break;
         case 2:
            var3.add("RSA");
            break;
         case 3:
            var3.add("RSA");
            var3.add("RSA_EXPORT");
            break;
         case 4:
            var3.add("RSA");
            var3.add("DH");
            var3.add("DiffieHellman");
            var3.add("DH_RSA");
            break;
         case 5:
            var3.add("DSA");
            var3.add("DSS");
            var3.add("DH");
            var3.add("DiffieHellman");
            var3.add("DH_DSS");
            break;
         case 6:
            var3.add("DSA");
            var3.add("DSS");
            var3.add("DH");
            var3.add("DHE");
            var3.add("DiffieHellman");
            var3.add("DHE_DSS");
            break;
         case 7:
            var3.add("RSA");
            var3.add("DH");
            var3.add("DHE");
            var3.add("DiffieHellman");
            var3.add("DHE_RSA");
            break;
         case 8:
            if (!var2) {
               var3.add("ANON");
               var3.add("DH");
               var3.add("DiffieHellman");
               var3.add("DH_ANON");
            }
            break;
         case 9:
            var3.add("ECDH");
            var3.add("ECDSA");
            var3.add("ECDH_ECDSA");
            break;
         case 10:
            var3.add("ECDH");
            var3.add("RSA");
            var3.add("ECDH_RSA");
            break;
         case 11:
            var3.add("ECDHE");
            var3.add("ECDSA");
            var3.add("ECDHE_ECDSA");
            break;
         case 12:
            var3.add("ECDHE");
            var3.add("RSA");
            var3.add("ECDHE_RSA");
            break;
         case 13:
            if (!var2) {
               var3.add("ECDH");
               var3.add("ANON");
               var3.add("ECDH_ANON");
            }
         case 14:
         case 15:
         default:
            break;
         case 16:
            if (!var2) {
               var3.add("KRB5");
            }
            break;
         case 17:
            if (!var2) {
               var3.add("KRB5_EXPORT");
            }
         }

         return var3;
      }

      protected Set<String> decomposes(CipherSuite.BulkCipher var1) {
         HashSet var2 = new HashSet();
         if (var1.transformation != null) {
            throw new RuntimeException("BS JSSE Exception");
         } else {
            return var2;
         }
      }

      protected Set<String> decomposes(CipherSuite.MacAlg var1) {
         HashSet var2 = new HashSet();
         if (var1 == CipherSuite.M_MD5) {
            var2.add("MD5");
            var2.add("HmacMD5");
         } else if (var1 == CipherSuite.M_SHA) {
            var2.add("SHA1");
            var2.add("SHA-1");
            var2.add("HmacSHA1");
         } else if (var1 == CipherSuite.M_SHA256) {
            var2.add("SHA256");
            var2.add("SHA-256");
            var2.add("HmacSHA256");
         } else if (var1 == CipherSuite.M_SHA384) {
            var2.add("SHA384");
            var2.add("SHA-384");
            var2.add("HmacSHA384");
         }

         return var2;
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

   private static class SupportedSignatureAlgorithmConstraints implements AlgorithmConstraints {
      private String[] supportedAlgorithms;

      SupportedSignatureAlgorithmConstraints(String[] var1) {
         if (var1 != null) {
            this.supportedAlgorithms = (String[])var1.clone();
         } else {
            this.supportedAlgorithms = null;
         }

      }

      public boolean permits(Set<CryptoPrimitive> var1, String var2, AlgorithmParameters var3) {
         if (var2 != null && var2.length() != 0) {
            if (var1 != null && !var1.isEmpty()) {
               if (this.supportedAlgorithms != null && this.supportedAlgorithms.length != 0) {
                  int var4 = var2.indexOf("and");
                  if (var4 > 0) {
                     var2 = var2.substring(0, var4);
                  }

                  String[] var8 = this.supportedAlgorithms;
                  int var7 = this.supportedAlgorithms.length;

                  for(int var6 = 0; var6 < var7; ++var6) {
                     String var5 = var8[var6];
                     if (var2.equalsIgnoreCase(var5)) {
                        return true;
                     }
                  }

                  return false;
               } else {
                  return false;
               }
            } else {
               throw new IllegalArgumentException("No cryptographic primitive specified");
            }
         } else {
            throw new IllegalArgumentException("No algorithm name specified");
         }
      }

      public final boolean permits(Set<CryptoPrimitive> var1, Key var2) {
         return true;
      }

      public final boolean permits(Set<CryptoPrimitive> var1, String var2, Key var3, AlgorithmParameters var4) {
         if (var2 != null && var2.length() != 0) {
            return this.permits(var1, var2, var4);
         } else {
            throw new IllegalArgumentException("No algorithm name specified");
         }
      }
   }

   private static class TLSDisabledAlgConstraints extends SSLAlgorithmConstraints.BasicDisabledAlgConstraints {
      TLSDisabledAlgConstraints() {
         super("jdk.tls.disabledAlgorithms");
      }

      protected Set<String> decomposes(String var1) {
         if (var1.startsWith("SSL_") || var1.startsWith("TLS_")) {
            CipherSuite var2 = null;

            try {
               var2 = CipherSuite.valueOf(var1);
            } catch (IllegalArgumentException var4) {
               ;
            }

            if (var2 != null) {
               HashSet var3 = new HashSet();
               if (var2.keyExchange != null) {
                  var3.addAll(this.decomposes(var2.keyExchange, false));
               }

               if (var2.cipher != null) {
                  var3.addAll(this.decomposes(var2.cipher));
               }

               if (var2.macAlg != null) {
                  var3.addAll(this.decomposes(var2.macAlg));
               }

               return var3;
            }
         }

         throw new RuntimeException("BS JSSE Exception");
      }
   }

   private static class X509DisabledAlgConstraints extends SSLAlgorithmConstraints.BasicDisabledAlgConstraints {
      X509DisabledAlgConstraints() {
         super("jdk.certpath.disabledAlgorithms");
      }

      protected Set<String> decomposes(String var1) {
         if (var1.startsWith("SSL_") || var1.startsWith("TLS_")) {
            CipherSuite var2 = null;

            try {
               var2 = CipherSuite.valueOf(var1);
            } catch (IllegalArgumentException var4) {
               ;
            }

            if (var2 != null) {
               HashSet var3 = new HashSet();
               if (var2.keyExchange != null) {
                  var3.addAll(this.decomposes(var2.keyExchange, true));
               }

               return var3;
            }
         }

         throw new RuntimeException("BS JSSE Exception");
      }
   }
}
