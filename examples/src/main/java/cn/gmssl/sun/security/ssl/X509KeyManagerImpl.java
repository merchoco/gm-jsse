package cn.gmssl.sun.security.ssl;

import java.lang.ref.Reference;
import java.lang.ref.SoftReference;
import java.net.Socket;
import java.security.AlgorithmConstraints;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.KeyStore.Builder;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;

final class X509KeyManagerImpl extends X509ExtendedKeyManager implements X509KeyManager {
   private static final Debug debug = Debug.getInstance("ssl");
   private static final boolean useDebug;
   private static Date verificationDate;
   private final List<Builder> builders;
   private final AtomicLong uidCounter;
   private final Map<String, Reference<PrivateKeyEntry>> entryCacheMap;

   static {
      useDebug = debug != null && Debug.isOn("keymanager");
   }

   X509KeyManagerImpl(Builder var1) {
      this(Collections.singletonList(var1));
   }

   X509KeyManagerImpl(List<Builder> var1) {
      this.builders = var1;
      this.uidCounter = new AtomicLong();
      this.entryCacheMap = Collections.synchronizedMap(new X509KeyManagerImpl.SizedMap((X509KeyManagerImpl.SizedMap)null));
   }

   public X509Certificate[] getCertificateChain(String var1) {
      PrivateKeyEntry var2 = this.getEntry(var1);
      return var2 == null ? null : (X509Certificate[])var2.getCertificateChain();
   }

   public PrivateKey getPrivateKey(String var1) {
      PrivateKeyEntry var2 = this.getEntry(var1);
      return var2 == null ? null : var2.getPrivateKey();
   }

   public String chooseClientAlias(String[] var1, Principal[] var2, Socket var3) {
      return this.chooseAlias(getKeyTypes(var1), var2, X509KeyManagerImpl.CheckType.CLIENT, this.getAlgorithmConstraints(var3));
   }

   public String chooseEngineClientAlias(String[] var1, Principal[] var2, SSLEngine var3) {
      return this.chooseAlias(getKeyTypes(var1), var2, X509KeyManagerImpl.CheckType.CLIENT, this.getAlgorithmConstraints(var3));
   }

   public String chooseServerAlias(String var1, Principal[] var2, Socket var3) {
      return this.chooseAlias(getKeyTypes(var1), var2, X509KeyManagerImpl.CheckType.SERVER, this.getAlgorithmConstraints(var3));
   }

   public String chooseEngineServerAlias(String var1, Principal[] var2, SSLEngine var3) {
      return this.chooseAlias(getKeyTypes(var1), var2, X509KeyManagerImpl.CheckType.SERVER, this.getAlgorithmConstraints(var3));
   }

   public String[] getClientAliases(String var1, Principal[] var2) {
      return this.getAliases(var1, var2, X509KeyManagerImpl.CheckType.CLIENT, (AlgorithmConstraints)null);
   }

   public String[] getServerAliases(String var1, Principal[] var2) {
      return this.getAliases(var1, var2, X509KeyManagerImpl.CheckType.SERVER, (AlgorithmConstraints)null);
   }

   private AlgorithmConstraints getAlgorithmConstraints(Socket var1) {
      if (var1 != null && var1.isConnected() && var1 instanceof SSLSocket) {
         SSLSocket var2 = (SSLSocket)var1;
         SSLSession var3 = var2.getHandshakeSession();
         if (var3 != null) {
            ProtocolVersion var4 = ProtocolVersion.valueOf(var3.getProtocol());
            if (var4.v >= ProtocolVersion.TLS12.v) {
               String[] var5 = null;
               if (var3 instanceof ExtendedSSLSession) {
                  ExtendedSSLSession var6 = (ExtendedSSLSession)var3;
                  var5 = var6.getPeerSupportedSignatureAlgorithms();
               }

               return new SSLAlgorithmConstraints(var2, var5, true);
            }
         }

         return new SSLAlgorithmConstraints(var2, true);
      } else {
         return new SSLAlgorithmConstraints((SSLSocket)null, true);
      }
   }

   private AlgorithmConstraints getAlgorithmConstraints(SSLEngine var1) {
      if (var1 != null) {
         SSLSession var2 = var1.getHandshakeSession();
         if (var2 != null) {
            ProtocolVersion var3 = ProtocolVersion.valueOf(var2.getProtocol());
            if (var3.v >= ProtocolVersion.TLS12.v) {
               String[] var4 = null;
               if (var2 instanceof ExtendedSSLSession) {
                  ExtendedSSLSession var5 = (ExtendedSSLSession)var2;
                  var4 = var5.getPeerSupportedSignatureAlgorithms();
               }

               return new SSLAlgorithmConstraints(var1, var4, true);
            }
         }
      }

      return new SSLAlgorithmConstraints(var1, true);
   }

   private String makeAlias(X509KeyManagerImpl.EntryStatus var1) {
      return this.uidCounter.incrementAndGet() + "." + var1.builderIndex + "." + var1.alias;
   }

   private PrivateKeyEntry getEntry(String var1) {
      if (var1 == null) {
         return null;
      } else {
         Reference var2 = (Reference)this.entryCacheMap.get(var1);
         PrivateKeyEntry var3 = var2 != null ? (PrivateKeyEntry)var2.get() : null;
         if (var3 != null) {
            return var3;
         } else {
            int var4 = var1.indexOf(46);
            int var5 = var1.indexOf(46, var4 + 1);
            if (var4 != -1 && var5 != var4) {
               try {
                  int var6 = Integer.parseInt(var1.substring(var4 + 1, var5));
                  String var7 = var1.substring(var5 + 1);
                  Builder var8 = (Builder)this.builders.get(var6);
                  KeyStore var9 = var8.getKeyStore();
                  Entry var10 = var9.getEntry(var7, var8.getProtectionParameter(var1));
                  if (!(var10 instanceof PrivateKeyEntry)) {
                     return null;
                  } else {
                     var3 = (PrivateKeyEntry)var10;
                     this.entryCacheMap.put(var1, new SoftReference(var3));
                     return var3;
                  }
               } catch (Exception var11) {
                  return null;
               }
            } else {
               return null;
            }
         }
      }
   }

   private static List<X509KeyManagerImpl.KeyType> getKeyTypes(String... var0) {
      if (var0 != null && var0.length != 0 && var0[0] != null) {
         ArrayList var1 = new ArrayList(var0.length);
         String[] var5 = var0;
         int var4 = var0.length;

         for(int var3 = 0; var3 < var4; ++var3) {
            String var2 = var5[var3];
            var1.add(new X509KeyManagerImpl.KeyType(var2));
         }

         return var1;
      } else {
         return null;
      }
   }

   private String chooseAlias(List<X509KeyManagerImpl.KeyType> var1, Principal[] var2, X509KeyManagerImpl.CheckType var3, AlgorithmConstraints var4) {
      if (var1 != null && var1.size() != 0) {
         Set var5 = this.getIssuerSet(var2);
         ArrayList var6 = null;
         int var7 = 0;

         for(int var8 = this.builders.size(); var7 < var8; ++var7) {
            try {
               List var9 = this.getAliases(var7, var1, var5, false, var3, var4);
               if (var9 != null) {
                  X509KeyManagerImpl.EntryStatus var10 = (X509KeyManagerImpl.EntryStatus)var9.get(0);
                  if (var10.checkResult == X509KeyManagerImpl.CheckResult.OK) {
                     if (useDebug) {
                        debug.println("KeyMgr: choosing key: " + var10);
                     }

                     return this.makeAlias(var10);
                  }

                  if (var6 == null) {
                     var6 = new ArrayList();
                  }

                  var6.addAll(var9);
               }
            } catch (Exception var11) {
               ;
            }
         }

         if (var6 == null) {
            if (useDebug) {
               debug.println("KeyMgr: no matching key found");
            }

            return null;
         } else {
            Collections.sort(var6);
            if (useDebug) {
               debug.println("KeyMgr: no good matching key found, returning best match out of:");
               debug.println(var6.toString());
            }

            return this.makeAlias((X509KeyManagerImpl.EntryStatus)var6.get(0));
         }
      } else {
         return null;
      }
   }

   public String[] getAliases(String var1, Principal[] var2, X509KeyManagerImpl.CheckType var3, AlgorithmConstraints var4) {
      if (var1 == null) {
         return null;
      } else {
         Set var5 = this.getIssuerSet(var2);
         List var6 = getKeyTypes(var1);
         ArrayList var7 = null;
         int var8 = 0;

         for(int var9 = this.builders.size(); var8 < var9; ++var8) {
            try {
               List var10 = this.getAliases(var8, var6, var5, true, var3, var4);
               if (var10 != null) {
                  if (var7 == null) {
                     var7 = new ArrayList();
                  }

                  var7.addAll(var10);
               }
            } catch (Exception var11) {
               ;
            }
         }

         if (var7 != null && var7.size() != 0) {
            Collections.sort(var7);
            if (useDebug) {
               debug.println("KeyMgr: getting aliases: " + var7);
            }

            return this.toAliases(var7);
         } else {
            if (useDebug) {
               debug.println("KeyMgr: no matching alias found");
            }

            return null;
         }
      }
   }

   private String[] toAliases(List<X509KeyManagerImpl.EntryStatus> var1) {
      String[] var2 = new String[var1.size()];
      int var3 = 0;

      X509KeyManagerImpl.EntryStatus var4;
      for(Iterator var5 = var1.iterator(); var5.hasNext(); var2[var3++] = this.makeAlias(var4)) {
         var4 = (X509KeyManagerImpl.EntryStatus)var5.next();
      }

      return var2;
   }

   private Set<Principal> getIssuerSet(Principal[] var1) {
      return var1 != null && var1.length != 0 ? new HashSet(Arrays.asList(var1)) : null;
   }

   private List<X509KeyManagerImpl.EntryStatus> getAliases(int var1, List<X509KeyManagerImpl.KeyType> var2, Set<Principal> var3, boolean var4, X509KeyManagerImpl.CheckType var5, AlgorithmConstraints var6) throws Exception {
      Builder var7 = (Builder)this.builders.get(var1);
      KeyStore var8 = var7.getKeyStore();
      ArrayList var9 = null;
      Date var10 = verificationDate;
      boolean var11 = false;
      Enumeration var12 = var8.aliases();

      while(true) {
         while(true) {
            String var13;
            Certificate[] var14;
            boolean var15;
            int var17;
            do {
               do {
                  do {
                     do {
                        if (!var12.hasMoreElements()) {
                           return var9;
                        }

                        var13 = (String)var12.nextElement();
                     } while(!var8.isKeyEntry(var13));

                     var14 = var8.getCertificateChain(var13);
                  } while(var14 == null);
               } while(var14.length == 0);

               var15 = false;
               Certificate[] var19 = var14;
               int var18 = var14.length;

               for(var17 = 0; var17 < var18; ++var17) {
                  Certificate var16 = var19[var17];
                  if (!(var16 instanceof X509Certificate)) {
                     var15 = true;
                     break;
                  }
               }
            } while(var15);

            int var24 = -1;
            var17 = 0;

            for(Iterator var27 = var2.iterator(); var27.hasNext(); ++var17) {
               X509KeyManagerImpl.KeyType var25 = (X509KeyManagerImpl.KeyType)var27.next();
               if (var25.matches(var14)) {
                  var24 = var17;
                  break;
               }
            }

            if (var24 == -1) {
               if (useDebug) {
                  debug.println("Ignoring alias " + var13 + ": key algorithm does not match");
               }
            } else {
               if (var3 != null) {
                  boolean var26 = false;
                  Certificate[] var22 = var14;
                  int var21 = var14.length;

                  for(int var20 = 0; var20 < var21; ++var20) {
                     Certificate var28 = var22[var20];
                     X509Certificate var23 = (X509Certificate)var28;
                     if (var3.contains(var23.getIssuerX500Principal())) {
                        var26 = true;
                        break;
                     }
                  }

                  if (!var26) {
                     if (useDebug) {
                        debug.println("Ignoring alias " + var13 + ": issuers do not match");
                     }
                     continue;
                  }
               }

               if (var6 != null && !conformsToAlgorithmConstraints(var6, var14)) {
                  if (useDebug) {
                     debug.println("Ignoring alias " + var13 + ": certificate list does not conform to " + "algorithm constraints");
                  }
               } else {
                  if (var10 == null) {
                     var10 = new Date();
                  }

                  X509KeyManagerImpl.CheckResult var29 = var5.check((X509Certificate)var14[0], var10);
                  X509KeyManagerImpl.EntryStatus var30 = new X509KeyManagerImpl.EntryStatus(var1, var24, var13, var14, var29);
                  if (!var11 && var29 == X509KeyManagerImpl.CheckResult.OK && var24 == 0) {
                     var11 = true;
                  }

                  if (var11 && !var4) {
                     return Collections.singletonList(var30);
                  }

                  if (var9 == null) {
                     var9 = new ArrayList();
                  }

                  var9.add(var30);
               }
            }
         }
      }
   }

   private static boolean conformsToAlgorithmConstraints(AlgorithmConstraints var0, Certificate[] var1) {
      return true;
   }

   private static enum CheckResult {
      OK,
      EXPIRED,
      EXTENSION_MISMATCH;
   }

   private static enum CheckType {
      NONE(new HashSet<String>()),
      CLIENT(new HashSet(Arrays.asList("2.5.29.37.0", "1.3.6.1.5.5.7.3.2"))),
      SERVER(new HashSet(Arrays.asList("2.5.29.37.0", "1.3.6.1.5.5.7.3.1", "2.16.840.1.113730.4.1", "1.3.6.1.4.1.311.10.3.3")));

      final Set<String> validEku;

      private CheckType(Set<String> var3) {
         this.validEku = var3;
      }

      private static boolean getBit(boolean[] var0, int var1) {
         return var1 < var0.length && var0[var1];
      }

      X509KeyManagerImpl.CheckResult check(X509Certificate var1, Date var2) {
         if (this == NONE) {
            return X509KeyManagerImpl.CheckResult.OK;
         } else {
            try {
               List var3 = var1.getExtendedKeyUsage();
               if (var3 != null && Collections.disjoint(this.validEku, var3)) {
                  return X509KeyManagerImpl.CheckResult.EXTENSION_MISMATCH;
               }

               boolean[] var4 = var1.getKeyUsage();
               if (var4 != null) {
                  String var5 = var1.getPublicKey().getAlgorithm();
                  boolean var6 = getBit(var4, 0);
                  if (var5.equals("RSA")) {
                     if (!var6 && (this == CLIENT || !getBit(var4, 2))) {
                        return X509KeyManagerImpl.CheckResult.EXTENSION_MISMATCH;
                     }
                  } else if (var5.equals("DSA")) {
                     if (!var6) {
                        return X509KeyManagerImpl.CheckResult.EXTENSION_MISMATCH;
                     }
                  } else if (var5.equals("DH")) {
                     if (!getBit(var4, 4)) {
                        return X509KeyManagerImpl.CheckResult.EXTENSION_MISMATCH;
                     }
                  } else if (var5.equals("EC")) {
                     if (!var6) {
                        return X509KeyManagerImpl.CheckResult.EXTENSION_MISMATCH;
                     }

                     if (this == SERVER && !getBit(var4, 4)) {
                        return X509KeyManagerImpl.CheckResult.EXTENSION_MISMATCH;
                     }
                  }
               }
            } catch (CertificateException var8) {
               return X509KeyManagerImpl.CheckResult.EXTENSION_MISMATCH;
            }

            try {
               var1.checkValidity(var2);
               return X509KeyManagerImpl.CheckResult.OK;
            } catch (CertificateException var7) {
               return X509KeyManagerImpl.CheckResult.EXPIRED;
            }
         }
      }
   }

   private static class EntryStatus implements Comparable<X509KeyManagerImpl.EntryStatus> {
      final int builderIndex;
      final int keyIndex;
      final String alias;
      final X509KeyManagerImpl.CheckResult checkResult;

      EntryStatus(int var1, int var2, String var3, Certificate[] var4, X509KeyManagerImpl.CheckResult var5) {
         this.builderIndex = var1;
         this.keyIndex = var2;
         this.alias = var3;
         this.checkResult = var5;
      }

      public int compareTo(X509KeyManagerImpl.EntryStatus var1) {
         int var2 = this.checkResult.compareTo(var1.checkResult);
         return var2 == 0 ? this.keyIndex - var1.keyIndex : var2;
      }

      public String toString() {
         String var1 = this.alias + " (verified: " + this.checkResult + ")";
         return this.builderIndex == 0 ? var1 : "Builder #" + this.builderIndex + ", alias: " + var1;
      }
   }

   private static class KeyType {
      final String keyAlgorithm;
      final String sigKeyAlgorithm;

      KeyType(String var1) {
         int var2 = var1.indexOf("_");
         if (var2 == -1) {
            this.keyAlgorithm = var1;
            this.sigKeyAlgorithm = null;
         } else {
            this.keyAlgorithm = var1.substring(0, var2);
            this.sigKeyAlgorithm = var1.substring(var2 + 1);
         }

      }

      boolean matches(Certificate[] var1) {
         if (!var1[0].getPublicKey().getAlgorithm().equals(this.keyAlgorithm)) {
            return false;
         } else if (this.sigKeyAlgorithm == null) {
            return true;
         } else if (var1.length > 1) {
            return this.sigKeyAlgorithm.equals(var1[1].getPublicKey().getAlgorithm());
         } else {
            X509Certificate var2 = (X509Certificate)var1[0];
            String var3 = var2.getSigAlgName().toUpperCase(Locale.ENGLISH);
            String var4 = "WITH" + this.sigKeyAlgorithm.toUpperCase(Locale.ENGLISH);
            return var3.contains(var4);
         }
      }
   }

   private static class SizedMap<K, V> extends LinkedHashMap<K, V> {
      private SizedMap() {
      }

      protected boolean removeEldestEntry(java.util.Map.Entry<K, V> var1) {
         return this.size() > 10;
      }

      // $FF: synthetic method
      SizedMap(X509KeyManagerImpl.SizedMap var1) {
         this();
      }
   }
}
