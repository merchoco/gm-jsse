package cn.gmssl.sun.security.ssl;

import java.io.FileInputStream;
import java.net.Socket;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
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

public class SunX509KeyManagerImpl extends X509ExtendedKeyManager {
   private static final Debug debug = Debug.getInstance("ssl");
   private static final String[] STRING0 = new String[0];
   private Map<String, SunX509KeyManagerImpl.X509Credentials> credentialsMap = new HashMap();
   private Map<String, String[]> serverAliasCache = new HashMap();

   public SunX509KeyManagerImpl(KeyStore ks, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
      if (ks == null) {
         return;
      }
      for (Enumeration<String> aliases = ks.aliases();
           aliases.hasMoreElements(); ) {
         String alias = aliases.nextElement();
         if (!ks.isKeyEntry(alias)) {
            continue;
         }
         Key key = ks.getKey(alias, password);
         if (key instanceof PrivateKey == false) {
            continue;
         }
         Certificate[] certs = ks.getCertificateChain(alias);
         if ((certs == null) || (certs.length == 0) ||
                 !(certs[0] instanceof X509Certificate)) {
            continue;
         }
         if (!(certs instanceof X509Certificate[])) {
            Certificate[] tmp = new X509Certificate[certs.length];
            System.arraycopy(certs, 0, tmp, 0, certs.length);
            certs = tmp;
         }

         X509Credentials cred = new X509Credentials((PrivateKey) key,
                 (X509Certificate[]) certs);

         FileInputStream in1 = null;
         credentialsMap.put(alias, cred);
         if (debug != null && sun.security.util.Debug.isOn("keymanager")) {
            System.out.println("***");
            System.out.println("found key for : " + alias);
            for (int i = 0; i < certs.length; i++) {
               System.out.println("chain [" + i + "] = "
                       + certs[i]);
            }
            System.out.println("***");
         }
      }
   }

   public X509Certificate[] getCertificateChain(String var1) {
      if (var1 == null) {
         return null;
      } else {
         SunX509KeyManagerImpl.X509Credentials var2 = (SunX509KeyManagerImpl.X509Credentials)this.credentialsMap.get(var1);
         return var2 == null ? null : (X509Certificate[])var2.certificates.clone();
      }
   }

   public PrivateKey getPrivateKey(String var1) {
      if (var1 == null) {
         return null;
      } else {
         SunX509KeyManagerImpl.X509Credentials var2 = (SunX509KeyManagerImpl.X509Credentials)this.credentialsMap.get(var1);
         return var2 == null ? null : var2.privateKey;
      }
   }

   public String chooseClientAlias(String[] var1, Principal[] var2, Socket var3) {
      if (var1 == null) {
         return null;
      } else {
         for(int var4 = 0; var4 < var1.length; ++var4) {
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
      return this.chooseClientAlias(var1, var2, (Socket)null);
   }

   public String chooseServerAlias(String var1, Principal[] var2, Socket var3) {
      if (var1 == null) {
         return null;
      } else {
         String[] var4;
         if (var2 != null && var2.length != 0) {
            var4 = this.getServerAliases(var1, var2);
         } else {
            var4 = (String[])this.serverAliasCache.get(var1);
            if (var4 == null) {
               var4 = this.getServerAliases(var1, var2);
               if (var4 == null) {
                  var4 = STRING0;
               }

               this.serverAliasCache.put(var1, var4);
            }
         }

         if (var4 != null && var4.length > 0) {
            if (var1.equals("EC") || var1.equals("EC_EC")) {
               if (var4.length == 1) {
                  return var4[0];
               }

               if (var4.length > 1) {
                  return var4[0] + ":" + var4[1];
               }
            }

            return var4[0];
         } else {
            return null;
         }
      }
   }

   public String chooseEngineServerAlias(String var1, Principal[] var2, SSLEngine var3) {
      return this.chooseServerAlias(var1, var2, (Socket)null);
   }

   public String[] getClientAliases(String var1, Principal[] var2) {
      return this.getAliases(var1, var2);
   }

   public String[] getServerAliases(String var1, Principal[] var2) {
      return this.getAliases(var1, var2);
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
               SunX509KeyManagerImpl.X509Credentials var9;
               while(true) {
                  X509Certificate[] var10;
                  do {
                     if (!var7.hasNext()) {
                        String[] var14 = (String[])var5.toArray(STRING0);
                        return var14.length == 0 ? null : var14;
                     }

                     Entry var6 = (Entry)var7.next();
                     var8 = (String)var6.getKey();
                     var9 = (SunX509KeyManagerImpl.X509Credentials)var6.getValue();
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
                     if (var11.equals("1.2.156.10197.1.501") || var11.toLowerCase().contains("sm3withsm2")) {
                        break;
                     }

                     String var12 = "WITH" + var3.toUpperCase(Locale.ENGLISH);
                     if (var11.contains(var12)) {
                        break;
                     }
                  }
               }

               if (((Object[])var2).length == 0) {
                  var5.add(var8);
                  if (debug != null && Debug.isOn("keymanager")) {
                     System.out.println("matching alias: " + var8);
                  }
               } else {
                  Set var15 = var9.getIssuerX500Principals();

                  for(int var16 = 0; var16 < var13.length; ++var16) {
                     if (var15.contains(((Object[])var2)[var16])) {
                        var5.add(var8);
                        if (debug != null && Debug.isOn("keymanager")) {
                           System.out.println("matching alias: " + var8);
                        }
                        break;
                     }
                  }
               }
            }
         }
      }
   }

   public static X500Principal[] convertPrincipals(Principal[] var0) {
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

   protected static class X509Credentials {
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
