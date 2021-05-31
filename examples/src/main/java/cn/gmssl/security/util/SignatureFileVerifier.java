package cn.gmssl.security.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.CodeSigner;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.Timestamp;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map.Entry;
import java.util.jar.Attributes;
import java.util.jar.JarException;
import java.util.jar.Manifest;
import java.util.jar.Attributes.Name;
import sun.misc.BASE64Decoder;
import sun.security.jca.Providers;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.PKCS9Attribute;
import sun.security.pkcs.PKCS9Attributes;
import sun.security.pkcs.SignerInfo;
import sun.security.timestamp.TimestampToken;

public class SignatureFileVerifier {
   private static final Debug debug = Debug.getInstance("jar");
   private ArrayList<CodeSigner[]> signerCache;
   private static final String ATTR_DIGEST;
   private PKCS7 block;
   private byte[] sfBytes;
   private String name;
   private ManifestDigester md;
   private HashMap<String, MessageDigest> createdDigests;
   private boolean workaround = false;
   private CertificateFactory certificateFactory = null;
   private static final char[] hexc;

   static {
      ATTR_DIGEST = "-DIGEST-Manifest-Main-Attributes".toUpperCase(Locale.ENGLISH);
      hexc = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
   }

   public SignatureFileVerifier(ArrayList<CodeSigner[]> var1, ManifestDigester var2, String var3, byte[] var4) throws IOException, NoSuchProviderException, CertificateException {
      Object var5 = null;

      try {
         var5 = Providers.startJarVerification();
         this.block = new PKCS7(var4);
         this.sfBytes = this.block.getContentInfo().getData();
         this.certificateFactory = CertificateFactory.getInstance("X509", "GMJCE");
      } finally {
         Providers.stopJarVerification(var5);
      }

      this.name = var3.substring(0, var3.lastIndexOf(".")).toUpperCase(Locale.ENGLISH);
      this.md = var2;
      this.signerCache = var1;
   }

   public boolean needSignatureFileBytes() {
      return this.sfBytes == null;
   }

   public boolean needSignatureFile(String var1) {
      return this.name.equalsIgnoreCase(var1);
   }

   public void setSignatureFile(byte[] var1) {
      this.sfBytes = var1;
   }

   public static boolean isBlockOrSF(String var0) {
      return var0.endsWith(".SF") || var0.endsWith(".DSA") || var0.endsWith(".RSA") || var0.endsWith(".EC");
   }

   private MessageDigest getDigest(String var1) {
      if (this.createdDigests == null) {
         this.createdDigests = new HashMap();
      }

      MessageDigest var2 = (MessageDigest)this.createdDigests.get(var1);
      if (var2 == null) {
         try {
            var2 = MessageDigest.getInstance(var1);
            this.createdDigests.put(var1, var2);
         } catch (NoSuchAlgorithmException var4) {
            ;
         }
      }

      return var2;
   }

   public void process(Hashtable<String, CodeSigner[]> var1, List var2) throws IOException, SignatureException, NoSuchAlgorithmException, JarException, CertificateException {
      Object var3 = null;

      try {
         var3 = Providers.startJarVerification();
         this.processImpl(var1, var2);
      } finally {
         Providers.stopJarVerification(var3);
      }

   }

   private void processImpl(Hashtable<String, CodeSigner[]> var1, List var2) throws IOException, SignatureException, NoSuchAlgorithmException, JarException, CertificateException {
      Manifest var3 = new Manifest();
      var3.read(new ByteArrayInputStream(this.sfBytes));
      String var4 = var3.getMainAttributes().getValue(Name.SIGNATURE_VERSION);
      if (var4 != null && var4.equalsIgnoreCase("1.0")) {
         SignerInfo[] var5 = this.block.verify(this.sfBytes);
         if (var5 == null) {
            throw new SecurityException("cannot verify signature block file " + this.name);
         } else {
            BASE64Decoder var6 = new BASE64Decoder();
            CodeSigner[] var7 = this.getSigners(var5, this.block);
            if (var7 != null) {
               Iterator var8 = var3.getEntries().entrySet().iterator();
               boolean var9 = this.verifyManifestHash(var3, this.md, var6, var2);
               if (!var9 && !this.verifyManifestMainAttrs(var3, this.md, var6)) {
                  throw new SecurityException("Invalid signature file digest for Manifest main attributes");
               } else {
                  while(true) {
                     while(var8.hasNext()) {
                        Entry var10 = (Entry)var8.next();
                        String var11 = (String)var10.getKey();
                        if (!var9 && !this.verifySection((Attributes)var10.getValue(), var11, this.md, var6)) {
                           if (debug != null) {
                              debug.println("processSignature unsigned name = " + var11);
                           }
                        } else {
                           if (var11.startsWith("./")) {
                              var11 = var11.substring(2);
                           }

                           if (var11.startsWith("/")) {
                              var11 = var11.substring(1);
                           }

                           this.updateSigners(var7, var1, var11);
                           if (debug != null) {
                              debug.println("processSignature signed name = " + var11);
                           }
                        }
                     }

                     this.updateSigners(var7, var1, "META-INF/MANIFEST.MF");
                     return;
                  }
               }
            }
         }
      }
   }

   private boolean verifyManifestHash(Manifest var1, ManifestDigester var2, BASE64Decoder var3, List var4) throws IOException {
      Attributes var5 = var1.getMainAttributes();
      boolean var6 = false;
      Iterator var8 = var5.entrySet().iterator();

      while(var8.hasNext()) {
         Entry var7 = (Entry)var8.next();
         String var9 = var7.getKey().toString();
         if (var9.toUpperCase(Locale.ENGLISH).endsWith("-DIGEST-MANIFEST")) {
            String var10 = var9.substring(0, var9.length() - 16);
            var4.add(var9);
            var4.add(var7.getValue());
            MessageDigest var11 = this.getDigest(var10);
            if (var11 != null) {
               byte[] var12 = var2.manifestDigest(var11);
               byte[] var13 = var3.decodeBuffer((String)var7.getValue());
               if (debug != null) {
                  debug.println("Signature File: Manifest digest " + var11.getAlgorithm());
                  debug.println("  sigfile  " + toHex(var13));
                  debug.println("  computed " + toHex(var12));
                  debug.println();
               }

               if (MessageDigest.isEqual(var12, var13)) {
                  var6 = true;
               }
            }
         }
      }

      return var6;
   }

   private boolean verifyManifestMainAttrs(Manifest var1, ManifestDigester var2, BASE64Decoder var3) throws IOException {
      Attributes var4 = var1.getMainAttributes();
      boolean var5 = true;
      Iterator var7 = var4.entrySet().iterator();

      while(var7.hasNext()) {
         Entry var6 = (Entry)var7.next();
         String var8 = var6.getKey().toString();
         if (var8.toUpperCase(Locale.ENGLISH).endsWith(ATTR_DIGEST)) {
            String var9 = var8.substring(0, var8.length() - ATTR_DIGEST.length());
            MessageDigest var10 = this.getDigest(var9);
            if (var10 != null) {
               ManifestDigester.Entry var11 = var2.get("Manifest-Main-Attributes", false);
               byte[] var12 = var11.digest(var10);
               byte[] var13 = var3.decodeBuffer((String)var6.getValue());
               if (debug != null) {
                  debug.println("Signature File: Manifest Main Attributes digest " + var10.getAlgorithm());
                  debug.println("  sigfile  " + toHex(var13));
                  debug.println("  computed " + toHex(var12));
                  debug.println();
               }

               if (!MessageDigest.isEqual(var12, var13)) {
                  var5 = false;
                  if (debug != null) {
                     debug.println("Verification of Manifest main attributes failed");
                     debug.println();
                  }
                  break;
               }
            }
         }
      }

      return var5;
   }

   private boolean verifySection(Attributes var1, String var2, ManifestDigester var3, BASE64Decoder var4) throws IOException {
      boolean var5 = false;
      ManifestDigester.Entry var6 = var3.get(var2, this.block.isOldStyle());
      if (var6 == null) {
         throw new SecurityException("no manifiest section for signature file entry " + var2);
      } else {
         if (var1 != null) {
            Iterator var8 = var1.entrySet().iterator();

            while(var8.hasNext()) {
               Entry var7 = (Entry)var8.next();
               String var9 = var7.getKey().toString();
               if (var9.toUpperCase(Locale.ENGLISH).endsWith("-DIGEST")) {
                  String var10 = var9.substring(0, var9.length() - 7);
                  MessageDigest var11 = this.getDigest(var10);
                  if (var11 != null) {
                     boolean var12 = false;
                     byte[] var13 = var4.decodeBuffer((String)var7.getValue());
                     byte[] var14;
                     if (this.workaround) {
                        var14 = var6.digestWorkaround(var11);
                     } else {
                        var14 = var6.digest(var11);
                     }

                     if (debug != null) {
                        debug.println("Signature Block File: " + var2 + " digest=" + var11.getAlgorithm());
                        debug.println("  expected " + toHex(var13));
                        debug.println("  computed " + toHex(var14));
                        debug.println();
                     }

                     if (MessageDigest.isEqual(var14, var13)) {
                        var5 = true;
                        var12 = true;
                     } else if (!this.workaround) {
                        var14 = var6.digestWorkaround(var11);
                        if (MessageDigest.isEqual(var14, var13)) {
                           if (debug != null) {
                              debug.println("  re-computed " + toHex(var14));
                              debug.println();
                           }

                           this.workaround = true;
                           var5 = true;
                           var12 = true;
                        }
                     }

                     if (!var12) {
                        throw new SecurityException("invalid " + var11.getAlgorithm() + " signature file digest for " + var2);
                     }
                  }
               }
            }
         }

         return var5;
      }
   }

   private CodeSigner[] getSigners(SignerInfo[] var1, PKCS7 var2) throws IOException, NoSuchAlgorithmException, SignatureException, CertificateException {
      ArrayList var3 = null;

      for(int var4 = 0; var4 < var1.length; ++var4) {
         SignerInfo var5 = var1[var4];
         ArrayList var6 = var5.getCertificateChain(var2);
         CertPath var7 = this.certificateFactory.generateCertPath(var6);
         if (var3 == null) {
            var3 = new ArrayList();
         }

         var3.add(new CodeSigner(var7, this.getTimestamp(var5)));
         if (debug != null) {
            debug.println("Signature Block Certificate: " + var6.get(0));
         }
      }

      if (var3 != null) {
         return (CodeSigner[])var3.toArray(new CodeSigner[var3.size()]);
      } else {
         return null;
      }
   }

   private Timestamp getTimestamp(SignerInfo var1) throws IOException, NoSuchAlgorithmException, SignatureException, CertificateException {
      Timestamp var2 = null;
      PKCS9Attributes var3 = var1.getUnauthenticatedAttributes();
      if (var3 != null) {
         PKCS9Attribute var4 = var3.getAttribute("signatureTimestampToken");
         if (var4 != null) {
            PKCS7 var5 = new PKCS7((byte[])var4.getValue());
            byte[] var6 = var5.getContentInfo().getData();
            SignerInfo[] var7 = var5.verify(var6);
            ArrayList var8 = var7[0].getCertificateChain(var5);
            CertPath var9 = this.certificateFactory.generateCertPath(var8);
            TimestampToken var10 = new TimestampToken(var6);
            var2 = new Timestamp(var10.getDate(), var9);
         }
      }

      return var2;
   }

   static String toHex(byte[] var0) {
      StringBuffer var1 = new StringBuffer(var0.length * 2);

      for(int var2 = 0; var2 < var0.length; ++var2) {
         var1.append(hexc[var0[var2] >> 4 & 15]);
         var1.append(hexc[var0[var2] & 15]);
      }

      return var1.toString();
   }

   static boolean contains(CodeSigner[] var0, CodeSigner var1) {
      for(int var2 = 0; var2 < var0.length; ++var2) {
         if (var0[var2].equals(var1)) {
            return true;
         }
      }

      return false;
   }

   static boolean isSubSet(CodeSigner[] var0, CodeSigner[] var1) {
      if (var1 == var0) {
         return true;
      } else {
         for(int var3 = 0; var3 < var0.length; ++var3) {
            if (!contains(var1, var0[var3])) {
               return false;
            }
         }

         return true;
      }
   }

   static boolean matches(CodeSigner[] var0, CodeSigner[] var1, CodeSigner[] var2) {
      if (var1 == null && var0 == var2) {
         return true;
      } else if (var1 != null && !isSubSet(var1, var0)) {
         return false;
      } else if (!isSubSet(var2, var0)) {
         return false;
      } else {
         for(int var4 = 0; var4 < var0.length; ++var4) {
            boolean var5 = var1 != null && contains(var1, var0[var4]) || contains(var2, var0[var4]);
            if (!var5) {
               return false;
            }
         }

         return true;
      }
   }

   void updateSigners(CodeSigner[] var1, Hashtable<String, CodeSigner[]> var2, String var3) {
      CodeSigner[] var4 = (CodeSigner[])var2.get(var3);

      CodeSigner[] var5;
      for(int var6 = this.signerCache.size() - 1; var6 != -1; --var6) {
         var5 = (CodeSigner[])this.signerCache.get(var6);
         if (matches(var5, var4, var1)) {
            var2.put(var3, var5);
            return;
         }
      }

      if (var4 == null) {
         var5 = var1;
      } else {
         var5 = new CodeSigner[var4.length + var1.length];
         System.arraycopy(var4, 0, var5, 0, var4.length);
         System.arraycopy(var1, 0, var5, var4.length, var1.length);
      }

      this.signerCache.add(var5);
      var2.put(var3, var5);
   }
}
