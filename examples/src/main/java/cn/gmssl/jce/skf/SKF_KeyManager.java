package cn.gmssl.jce.skf;

import cn.gmssl.jce.provider.GMConf;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;

public class SKF_KeyManager extends X509ExtendedKeyManager {
   private static final String[] STRING0 = new String[0];
   private Map<String, SKF_KeyManager.X509Credentials> credentialsMap = new HashMap();
   private X509Certificate[] sigCert = null;
   private X509Certificate[] encCert = null;
   private PrivateKey sigPri = null;
   private PrivateKey encPri = null;

   public SKF_KeyManager(ICryptoProvider var1, X509Certificate[] var2) {
      try {
         X509Certificate var3 = var1.getCert(1);
         X509Certificate var4 = var1.getCert(0);
         if (var2 != null && var2.length > 0) {
            this.sigCert = new X509Certificate[1 + var2.length];
            this.sigCert[0] = var3;

            for(int var5 = 0; var5 < var2.length; ++var5) {
               this.sigCert[1 + var5] = var2[var5];
            }
         } else {
            this.sigCert = new X509Certificate[]{var3};
         }

         this.encCert = new X509Certificate[]{var4};
         this.sigPri = var1.getPrivateKey(1);
         this.encPri = var1.getPrivateKey(0);
         if (GMConf.skfDebug) {
            System.out.println("SKF_KeyManager sigPri=" + this.sigPri);
            System.out.println("SKF_KeyManager encPri=" + this.encPri);
         }

         SKF_KeyManager.X509Credentials var8 = new SKF_KeyManager.X509Credentials(this.sigPri, this.sigCert);
         this.credentialsMap.put("SKF_Sig", var8);
         SKF_KeyManager.X509Credentials var6 = new SKF_KeyManager.X509Credentials(this.encPri, this.encCert);
         this.credentialsMap.put("SKF_Enc", var6);
      } catch (Exception var7) {
         throw new RuntimeException(var7);
      }
   }

   public String[] getClientAliases(String var1, Principal[] var2) {
      return this.getAliases(var1, var2);
   }

   public String chooseClientAlias(String[] var1, Principal[] var2, Socket var3) {
      if (var1 == null) {
         return null;
      } else {
         for(int var4 = 0; var4 < var1.length; ++var4) {
            if (GMConf.skfDebug) {
               System.out.println("chooseClientAlias keyTypes[i]=" + var1[var4]);
            }

            String[] var5 = this.getClientAliases(var1[var4], var2);
            if (var5 != null && var5.length > 0) {
               if (var1[var4].equals("EC") || var1[var4].equals("EC_EC")) {
                  if (var5.length == 1) {
                     return var5[0];
                  }

                  if (var5.length > 1) {
                     return var5[0] + ":" + var5[1];
                  }
               }

               return var5[0];
            }
         }

         return null;
      }
   }

   public String chooseEngineClientAlias(String[] var1, Principal[] var2, SSLEngine var3) {
      if (var1 == null) {
         return null;
      } else {
         for(int var4 = 0; var4 < var1.length; ++var4) {
            if (GMConf.skfDebug) {
               System.out.println("chooseClientAlias keyTypes[i]=" + var1[var4]);
            }

            String[] var5 = this.getClientAliases(var1[var4], var2);
            if (var5 != null && var5.length > 0) {
               return var5[0];
            }
         }

         return null;
      }
   }

   public String[] getServerAliases(String var1, Principal[] var2) {
      throw new UnsupportedOperationException();
   }

   public String chooseServerAlias(String var1, Principal[] var2, Socket var3) {
      throw new UnsupportedOperationException();
   }

   public X509Certificate[] getCertificateChain(String var1) {
      if (GMConf.skfDebug) {
         System.out.println("getCertificateChain alias=" + var1);
      }

      if (var1.equals("SKF_Sig")) {
         return this.sigCert;
      } else {
         return var1.equals("SKF_Enc") ? this.encCert : null;
      }
   }

   public PrivateKey getPrivateKey(String var1) {
      if (GMConf.skfDebug) {
         System.out.println("getPrivateKey alias=" + var1);
      }

      if (var1.equals("SKF_Sig")) {
         return this.sigPri;
      } else {
         return var1.equals("SKF_Enc") ? this.encPri : null;
      }
   }

   private String[] getAliases(String var1, Principal[] var2) {
      if (var1 == null) {
         return null;
      } else {
         if (var2 == null) {
            var2 = new X500Principal[0];
         }

         if (!(var2 instanceof X500Principal[])) {
            var2 = convertPrincipals((Principal[])var2);
         }

         String var3;
         if (var1.contains("_")) {
            int var4 = var1.indexOf("_");
            var3 = var1.substring(var4 + 1);
            var1 = var1.substring(0, var4);
         } else {
            var3 = null;
         }

         X500Principal[] var13 = (X500Principal[])var2;
         ArrayList var5 = new ArrayList();
         Iterator var7 = this.credentialsMap.entrySet().iterator();

         while(true) {
            while(true) {
               String var8;
               SKF_KeyManager.X509Credentials var9;
               while(true) {
                  X509Certificate[] var10;
                  do {
                     if (!var7.hasNext()) {
                        String[] var14 = (String[])var5.toArray(STRING0);
                        return var14.length == 0 ? null : var14;
                     }

                     Entry var6 = (Entry)var7.next();
                     var8 = (String)var6.getKey();
                     var9 = (SKF_KeyManager.X509Credentials)var6.getValue();
                     var10 = var9.certificates;
                  } while(!var1.equals(var10[0].getPublicKey().getAlgorithm()));

                  if (var3 == null) {
                     break;
                  }

                  if (var10.length > 1) {
                     if (!var3.equals(var10[1].getPublicKey().getAlgorithm())) {
                        continue;
                     }
                     break;
                  } else {
                     String var11 = var10[0].getSigAlgName().toUpperCase(Locale.ENGLISH);
                     String var12 = "WITH" + var3.toUpperCase(Locale.ENGLISH);
                     if (GMConf.skfDebug) {
                        System.out.println("getAliases sigAlgName=" + var11 + ",pattern=" + var12);
                     }

                     if (var11.contains(var12)) {
                        break;
                     }
                  }
               }

               if (((Object[])var2).length == 0) {
                  var5.add(var8);
               } else {
                  Set var15 = var9.getIssuerX500Principals();

                  for(int var16 = 0; var16 < var13.length; ++var16) {
                     if (var15.contains(((Object[])var2)[var16])) {
                        var5.add(var8);
                        break;
                     }
                  }
               }
            }
         }
      }
   }

   private static X500Principal[] convertPrincipals(Principal[] var0) {
      ArrayList var1 = new ArrayList(var0.length);

      for(int var2 = 0; var2 < var0.length; ++var2) {
         Principal var3 = var0[var2];
         if (var3 instanceof X500Principal) {
            var1.add((X500Principal)var3);
         } else {
            try {
               var1.add(new X500Principal(var3.getName()));
            } catch (IllegalArgumentException var5) {
               ;
            }
         }
      }

      return (X500Principal[])var1.toArray(new X500Principal[var1.size()]);
   }

   private static class X509Credentials {
      PrivateKey privateKey;
      X509Certificate[] certificates;
      private Set<X500Principal> issuerX500Principals;

      X509Credentials(PrivateKey var1, X509Certificate[] var2) {
         this.privateKey = var1;
         this.certificates = var2;
      }

      synchronized Set<X500Principal> getIssuerX500Principals() {
         if (this.issuerX500Principals == null) {
            this.issuerX500Principals = new HashSet();

            for(int var1 = 0; var1 < this.certificates.length; ++var1) {
               this.issuerX500Principals.add(this.certificates[var1].getIssuerX500Principal());
            }
         }

         return this.issuerX500Principals;
      }
   }
}
