package cn.gmssl.security.util;

import java.io.IOException;
import java.security.CodeSigner;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map.Entry;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarException;
import java.util.jar.Manifest;
import sun.misc.BASE64Decoder;
import sun.security.jca.Providers;

public class ManifestEntryVerifier {
   private static final Debug debug = Debug.getInstance("jar");
   HashMap<String, MessageDigest> createdDigests = new HashMap(11);
   ArrayList<MessageDigest> digests = new ArrayList();
   ArrayList<byte[]> manifestHashes = new ArrayList();
   private BASE64Decoder decoder = null;
   private String name = null;
   private Manifest man;
   private boolean skip = true;
   private JarEntry entry;
   private CodeSigner[] signers = null;
   private static final char[] hexc = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

   public ManifestEntryVerifier(Manifest var1) {
      this.decoder = new BASE64Decoder();
      this.man = var1;
   }

   public void setEntry(String var1, JarEntry var2) throws IOException {
      this.digests.clear();
      this.manifestHashes.clear();
      this.name = var1;
      this.entry = var2;
      this.skip = true;
      this.signers = null;
      if (this.man != null && var1 != null) {
         Attributes var3 = this.man.getAttributes(var1);
         if (var3 == null) {
            var3 = this.man.getAttributes("./" + var1);
            if (var3 == null) {
               var3 = this.man.getAttributes("/" + var1);
               if (var3 == null) {
                  return;
               }
            }
         }

         Iterator var5 = var3.entrySet().iterator();

         while(var5.hasNext()) {
            Entry var4 = (Entry)var5.next();
            String var6 = var4.getKey().toString();
            if (var6.toUpperCase(Locale.ENGLISH).endsWith("-DIGEST")) {
               String var7 = var6.substring(0, var6.length() - 7);
               MessageDigest var8 = (MessageDigest)this.createdDigests.get(var7);
               if (var8 == null) {
                  try {
                     var8 = MessageDigest.getInstance(var7, ManifestEntryVerifier.SunProviderHolder.instance);
                     this.createdDigests.put(var7, var8);
                  } catch (NoSuchAlgorithmException var10) {
                     ;
                  }
               }

               if (var8 != null) {
                  this.skip = false;
                  var8.reset();
                  this.digests.add(var8);
                  this.manifestHashes.add(this.decoder.decodeBuffer((String)var4.getValue()));
               }
            }
         }

      }
   }

   public void update(byte var1) {
      if (!this.skip) {
         for(int var2 = 0; var2 < this.digests.size(); ++var2) {
            ((MessageDigest)this.digests.get(var2)).update(var1);
         }

      }
   }

   public void update(byte[] var1, int var2, int var3) {
      if (!this.skip) {
         for(int var4 = 0; var4 < this.digests.size(); ++var4) {
            ((MessageDigest)this.digests.get(var4)).update(var1, var2, var3);
         }

      }
   }

   public JarEntry getEntry() {
      return this.entry;
   }

   public CodeSigner[] verify(Hashtable<String, CodeSigner[]> var1, Hashtable<String, CodeSigner[]> var2) throws JarException {
      if (this.skip) {
         return null;
      } else if (this.signers != null) {
         return this.signers;
      } else {
         for(int var3 = 0; var3 < this.digests.size(); ++var3) {
            MessageDigest var4 = (MessageDigest)this.digests.get(var3);
            byte[] var5 = (byte[])this.manifestHashes.get(var3);
            byte[] var6 = var4.digest();
            if (debug != null) {
               debug.println("Manifest Entry: " + this.name + " digest=" + var4.getAlgorithm());
               debug.println("  manifest " + toHex(var5));
               debug.println("  computed " + toHex(var6));
               debug.println();
            }

            if (!MessageDigest.isEqual(var6, var5)) {
               throw new SecurityException(var4.getAlgorithm() + " digest error for " + this.name);
            }
         }

         this.signers = (CodeSigner[])var2.remove(this.name);
         if (this.signers != null) {
            var1.put(this.name, this.signers);
         }

         return this.signers;
      }
   }

   static String toHex(byte[] var0) {
      StringBuffer var1 = new StringBuffer(var0.length * 2);

      for(int var2 = 0; var2 < var0.length; ++var2) {
         var1.append(hexc[var0[var2] >> 4 & 15]);
         var1.append(hexc[var0[var2] & 15]);
      }

      return var1.toString();
   }

   private static class SunProviderHolder {
      private static final Provider instance = Providers.getSunProvider();
   }
}
