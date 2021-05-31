package org.bc.jce.provider;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1InputStream;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1Set;
import org.bc.asn1.BEROctetString;
import org.bc.asn1.BEROutputStream;
import org.bc.asn1.DERBMPString;
import org.bc.asn1.DERNull;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.DEROutputStream;
import org.bc.asn1.DERSequence;
import org.bc.asn1.DERSet;
import org.bc.asn1.pkcs.AuthenticatedSafe;
import org.bc.asn1.pkcs.CertBag;
import org.bc.asn1.pkcs.ContentInfo;
import org.bc.asn1.pkcs.EncryptedData;
import org.bc.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bc.asn1.pkcs.MacData;
import org.bc.asn1.pkcs.PKCS12PBEParams;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.asn1.pkcs.Pfx;
import org.bc.asn1.pkcs.PrivateKeyInfo;
import org.bc.asn1.pkcs.SafeBag;
import org.bc.asn1.util.ASN1Dump;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.AuthorityKeyIdentifier;
import org.bc.asn1.x509.DigestInfo;
import org.bc.asn1.x509.Extension;
import org.bc.asn1.x509.SubjectKeyIdentifier;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.asn1.x509.X509ObjectIdentifiers;
import org.bc.jcajce.provider.symmetric.util.BCPBEKey;
import org.bc.jce.interfaces.BCKeyStore;
import org.bc.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bc.util.Arrays;
import org.bc.util.Strings;
import org.bc.util.encoders.Hex;

public class JDKPKCS12KeyStore extends KeyStoreSpi implements PKCSObjectIdentifiers, X509ObjectIdentifiers, BCKeyStore {
   private static final int SALT_SIZE = 20;
   private static final int MIN_ITERATIONS = 1024;
   private static final Provider bcProvider = new BouncyCastleProvider();
   private JDKPKCS12KeyStore.IgnoresCaseHashtable keys = new JDKPKCS12KeyStore.IgnoresCaseHashtable((JDKPKCS12KeyStore.IgnoresCaseHashtable)null);
   private Hashtable localIds = new Hashtable();
   private JDKPKCS12KeyStore.IgnoresCaseHashtable certs = new JDKPKCS12KeyStore.IgnoresCaseHashtable((JDKPKCS12KeyStore.IgnoresCaseHashtable)null);
   private Hashtable chainCerts = new Hashtable();
   private Hashtable keyCerts = new Hashtable();
   static final int NULL = 0;
   static final int CERTIFICATE = 1;
   static final int KEY = 2;
   static final int SECRET = 3;
   static final int SEALED = 4;
   static final int KEY_PRIVATE = 0;
   static final int KEY_PUBLIC = 1;
   static final int KEY_SECRET = 2;
   protected SecureRandom random = new SecureRandom();
   private CertificateFactory certFact;
   private ASN1ObjectIdentifier keyAlgorithm;
   private ASN1ObjectIdentifier certAlgorithm;

   public JDKPKCS12KeyStore(Provider var1, ASN1ObjectIdentifier var2, ASN1ObjectIdentifier var3) {
      this.keyAlgorithm = var2;
      this.certAlgorithm = var3;

      try {
         if (var1 != null) {
            this.certFact = CertificateFactory.getInstance("X.509", var1);
         } else {
            this.certFact = CertificateFactory.getInstance("X.509");
         }

      } catch (Exception var5) {
         throw new IllegalArgumentException("can't create cert factory - " + var5.toString());
      }
   }

   private SubjectKeyIdentifier createSubjectKeyId(PublicKey var1) {
      try {
         SubjectPublicKeyInfo var2 = new SubjectPublicKeyInfo((ASN1Sequence)ASN1Primitive.fromByteArray(var1.getEncoded()));
         return new SubjectKeyIdentifier(var2);
      } catch (Exception var3) {
         throw new RuntimeException("error creating key");
      }
   }

   public void setRandom(SecureRandom var1) {
      this.random = var1;
   }

   public Enumeration engineAliases() {
      Hashtable var1 = new Hashtable();
      Enumeration var2 = this.certs.keys();

      while(var2.hasMoreElements()) {
         var1.put(var2.nextElement(), "cert");
      }

      var2 = this.keys.keys();

      while(var2.hasMoreElements()) {
         String var3 = (String)var2.nextElement();
         if (var1.get(var3) == null) {
            var1.put(var3, "key");
         }
      }

      return var1.keys();
   }

   public boolean engineContainsAlias(String var1) {
      return this.certs.get(var1) != null || this.keys.get(var1) != null;
   }

   public void engineDeleteEntry(String var1) throws KeyStoreException {
      Key var2 = (Key)this.keys.remove(var1);
      Certificate var3 = (Certificate)this.certs.remove(var1);
      if (var3 != null) {
         this.chainCerts.remove(new JDKPKCS12KeyStore.CertId(var3.getPublicKey()));
      }

      if (var2 != null) {
         String var4 = (String)this.localIds.remove(var1);
         if (var4 != null) {
            var3 = (Certificate)this.keyCerts.remove(var4);
         }

         if (var3 != null) {
            this.chainCerts.remove(new JDKPKCS12KeyStore.CertId(var3.getPublicKey()));
         }
      }

   }

   public Certificate engineGetCertificate(String var1) {
      if (var1 == null) {
         throw new IllegalArgumentException("null alias passed to getCertificate.");
      } else {
         Certificate var2 = (Certificate)this.certs.get(var1);
         if (var2 == null) {
            String var3 = (String)this.localIds.get(var1);
            if (var3 != null) {
               var2 = (Certificate)this.keyCerts.get(var3);
            } else {
               var2 = (Certificate)this.keyCerts.get(var1);
            }
         }

         return var2;
      }
   }

   public String engineGetCertificateAlias(Certificate var1) {
      Enumeration var2 = this.certs.elements();
      Enumeration var3 = this.certs.keys();

      Certificate var4;
      String var5;
      while(var2.hasMoreElements()) {
         var4 = (Certificate)var2.nextElement();
         var5 = (String)var3.nextElement();
         if (var4.equals(var1)) {
            return var5;
         }
      }

      var2 = this.keyCerts.elements();
      var3 = this.keyCerts.keys();

      while(var2.hasMoreElements()) {
         var4 = (Certificate)var2.nextElement();
         var5 = (String)var3.nextElement();
         if (var4.equals(var1)) {
            return var5;
         }
      }

      return null;
   }

   public Certificate[] engineGetCertificateChain(String var1) {
      if (var1 == null) {
         throw new IllegalArgumentException("null alias passed to getCertificateChain.");
      } else if (!this.engineIsKeyEntry(var1)) {
         return null;
      } else {
         Object var2 = this.engineGetCertificate(var1);
         if (var2 == null) {
            return null;
         } else {
            Vector var3 = new Vector();

            while(var2 != null) {
               X509Certificate var4 = (X509Certificate)var2;
               Object var5 = null;
               byte[] var6 = var4.getExtensionValue(Extension.authorityKeyIdentifier.getId());
               if (var6 != null) {
                  try {
                     ASN1InputStream var7 = new ASN1InputStream(var6);
                     byte[] var8 = ((ASN1OctetString)var7.readObject()).getOctets();
                     var7 = new ASN1InputStream(var8);
                     AuthorityKeyIdentifier var9 = AuthorityKeyIdentifier.getInstance(var7.readObject());
                     if (var9.getKeyIdentifier() != null) {
                        var5 = (Certificate)this.chainCerts.get(new JDKPKCS12KeyStore.CertId(var9.getKeyIdentifier()));
                     }
                  } catch (IOException var13) {
                     throw new RuntimeException(var13.toString());
                  }
               }

               if (var5 == null) {
                  Principal var17 = var4.getIssuerDN();
                  Principal var18 = var4.getSubjectDN();
                  if (!var17.equals(var18)) {
                     Enumeration var19 = this.chainCerts.keys();

                     label63:
                     while(true) {
                        X509Certificate var10;
                        Principal var11;
                        do {
                           if (!var19.hasMoreElements()) {
                              break label63;
                           }

                           var10 = (X509Certificate)this.chainCerts.get(var19.nextElement());
                           var11 = var10.getSubjectDN();
                        } while(!var11.equals(var17));

                        try {
                           var4.verify(var10.getPublicKey());
                           var5 = var10;
                           break;
                        } catch (Exception var14) {
                           ;
                        }
                     }
                  }
               }

               var3.addElement(var2);
               if (var5 != var2) {
                  var2 = var5;
               } else {
                  var2 = null;
               }
            }

            Certificate[] var15 = new Certificate[var3.size()];

            for(int var16 = 0; var16 != var15.length; ++var16) {
               var15[var16] = (Certificate)var3.elementAt(var16);
            }

            return var15;
         }
      }
   }

   public Date engineGetCreationDate(String var1) {
      if (var1 == null) {
         throw new NullPointerException("alias == null");
      } else {
         return this.keys.get(var1) == null && this.certs.get(var1) == null ? null : new Date();
      }
   }

   public Key engineGetKey(String var1, char[] var2) throws NoSuchAlgorithmException, UnrecoverableKeyException {
      if (var1 == null) {
         throw new IllegalArgumentException("null alias passed to getKey.");
      } else {
         return (Key)this.keys.get(var1);
      }
   }

   public boolean engineIsCertificateEntry(String var1) {
      return this.certs.get(var1) != null && this.keys.get(var1) == null;
   }

   public boolean engineIsKeyEntry(String var1) {
      return this.keys.get(var1) != null;
   }

   public void engineSetCertificateEntry(String var1, Certificate var2) throws KeyStoreException {
      if (this.keys.get(var1) != null) {
         throw new KeyStoreException("There is a key entry with the name " + var1 + ".");
      } else {
         this.certs.put(var1, var2);
         this.chainCerts.put(new JDKPKCS12KeyStore.CertId(var2.getPublicKey()), var2);
      }
   }

   public void engineSetKeyEntry(String var1, byte[] var2, Certificate[] var3) throws KeyStoreException {
      throw new RuntimeException("operation not supported");
   }

   public void engineSetKeyEntry(String var1, Key var2, char[] var3, Certificate[] var4) throws KeyStoreException {
      if (!(var2 instanceof PrivateKey)) {
         throw new KeyStoreException("PKCS12 does not support non-PrivateKeys");
      } else if (var2 instanceof PrivateKey && var4 == null) {
         throw new KeyStoreException("no certificate chain for private key");
      } else {
         if (this.keys.get(var1) != null) {
            this.engineDeleteEntry(var1);
         }

         this.keys.put(var1, var2);
         if (var4 != null) {
            this.certs.put(var1, var4[0]);

            for(int var5 = 0; var5 != var4.length; ++var5) {
               this.chainCerts.put(new JDKPKCS12KeyStore.CertId(var4[var5].getPublicKey()), var4[var5]);
            }
         }

      }
   }

   public int engineSize() {
      Hashtable var1 = new Hashtable();
      Enumeration var2 = this.certs.keys();

      while(var2.hasMoreElements()) {
         var1.put(var2.nextElement(), "cert");
      }

      var2 = this.keys.keys();

      while(var2.hasMoreElements()) {
         String var3 = (String)var2.nextElement();
         if (var1.get(var3) == null) {
            var1.put(var3, "key");
         }
      }

      return var1.size();
   }

   protected PrivateKey unwrapKey(AlgorithmIdentifier var1, byte[] var2, char[] var3, boolean var4) throws IOException {
      String var5 = var1.getAlgorithm().getId();
      PKCS12PBEParams var6 = PKCS12PBEParams.getInstance(var1.getParameters());
      PBEKeySpec var7 = new PBEKeySpec(var3);

      try {
         SecretKeyFactory var9 = SecretKeyFactory.getInstance(var5, bcProvider);
         PBEParameterSpec var10 = new PBEParameterSpec(var6.getIV(), var6.getIterations().intValue());
         SecretKey var11 = var9.generateSecret(var7);
         ((BCPBEKey)var11).setTryWrongPKCS12Zero(var4);
         Cipher var12 = Cipher.getInstance(var5, bcProvider);
         var12.init(4, var11, var10);
         PrivateKey var8 = (PrivateKey)var12.unwrap(var2, "", 2);
         return var8;
      } catch (Exception var13) {
         throw new IOException("exception unwrapping private key - " + var13.toString());
      }
   }

   protected byte[] wrapKey(String var1, Key var2, PKCS12PBEParams var3, char[] var4) throws IOException {
      PBEKeySpec var5 = new PBEKeySpec(var4);

      try {
         SecretKeyFactory var7 = SecretKeyFactory.getInstance(var1, bcProvider);
         PBEParameterSpec var8 = new PBEParameterSpec(var3.getIV(), var3.getIterations().intValue());
         Cipher var9 = Cipher.getInstance(var1, bcProvider);
         var9.init(3, var7.generateSecret(var5), var8);
         byte[] var6 = var9.wrap(var2);
         return var6;
      } catch (Exception var10) {
         throw new IOException("exception encrypting data - " + var10.toString());
      }
   }

   protected byte[] cryptData(boolean var1, AlgorithmIdentifier var2, char[] var3, boolean var4, byte[] var5) throws IOException {
      String var6 = var2.getAlgorithm().getId();
      PKCS12PBEParams var7 = PKCS12PBEParams.getInstance(var2.getParameters());
      PBEKeySpec var8 = new PBEKeySpec(var3);

      try {
         SecretKeyFactory var9 = SecretKeyFactory.getInstance(var6, bcProvider);
         PBEParameterSpec var10 = new PBEParameterSpec(var7.getIV(), var7.getIterations().intValue());
         BCPBEKey var11 = (BCPBEKey)var9.generateSecret(var8);
         var11.setTryWrongPKCS12Zero(var4);
         Cipher var12 = Cipher.getInstance(var6, bcProvider);
         int var13 = var1 ? 1 : 2;
         var12.init(var13, var11, var10);
         return var12.doFinal(var5);
      } catch (Exception var14) {
         throw new IOException("exception decrypting data - " + var14.toString());
      }
   }

   public void engineLoad(InputStream var1, char[] var2) throws IOException {
      if (var1 != null) {
         if (var2 == null) {
            throw new NullPointerException("No password supplied for PKCS#12 KeyStore.");
         } else {
            BufferedInputStream var3 = new BufferedInputStream(var1);
            var3.mark(10);
            int var4 = var3.read();
            if (var4 != 48) {
               throw new IOException("stream does not represent a PKCS12 key store");
            } else {
               var3.reset();
               ASN1InputStream var5 = new ASN1InputStream(var3);
               ASN1Sequence var6 = (ASN1Sequence)var5.readObject();
               Pfx var7 = Pfx.getInstance(var6);
               ContentInfo var8 = var7.getAuthSafe();
               Vector var9 = new Vector();
               boolean var10 = false;
               boolean var11 = false;
               if (var7.getMacData() != null) {
                  MacData var12 = var7.getMacData();
                  DigestInfo var13 = var12.getMac();
                  AlgorithmIdentifier var14 = var13.getAlgorithmId();
                  byte[] var15 = var12.getSalt();
                  int var16 = var12.getIterationCount().intValue();
                  byte[] var17 = ((ASN1OctetString)var8.getContent()).getOctets();

                  try {
                     byte[] var18 = calculatePbeMac(var14.getObjectId(), var15, var16, var2, false, var17);
                     byte[] var19 = var13.getDigest();
                     if (!Arrays.constantTimeAreEqual(var18, var19)) {
                        if (var2.length > 0) {
                           throw new IOException("PKCS12 key store mac invalid - wrong password or corrupted file.");
                        }

                        var18 = calculatePbeMac(var14.getObjectId(), var15, var16, var2, true, var17);
                        if (!Arrays.constantTimeAreEqual(var18, var19)) {
                           throw new IOException("PKCS12 key store mac invalid - wrong password or corrupted file.");
                        }

                        var11 = true;
                     }
                  } catch (IOException var32) {
                     throw var32;
                  } catch (Exception var33) {
                     var33.printStackTrace();
                     throw new IOException("error constructing MAC: " + var33.toString());
                  }
               }

               this.keys = new JDKPKCS12KeyStore.IgnoresCaseHashtable((JDKPKCS12KeyStore.IgnoresCaseHashtable)null);
               this.localIds = new Hashtable();
               PKCS12BagAttributeCarrier var22;
               if (var8.getContentType().equals(data)) {
                  var5 = new ASN1InputStream(((ASN1OctetString)var8.getContent()).getOctets());
                  AuthenticatedSafe var34 = AuthenticatedSafe.getInstance(var5.readObject());
                  ContentInfo[] var36 = var34.getContentInfo();

                  for(int var38 = 0; var38 != var36.length; ++var38) {
                     if (var36[var38].getContentType().equals(data)) {
                        ASN1InputStream var41 = new ASN1InputStream(((ASN1OctetString)var36[var38].getContent()).getOctets());
                        ASN1Sequence var44 = (ASN1Sequence)var41.readObject();

                        for(int var48 = 0; var48 != var44.size(); ++var48) {
                           SafeBag var51 = SafeBag.getInstance(var44.getObjectAt(var48));
                           if (!var51.getBagId().equals(pkcs8ShroudedKeyBag)) {
                              if (var51.getBagId().equals(certBag)) {
                                 var9.addElement(var51);
                              } else {
                                 System.out.println("extra in data " + var51.getBagId());
                                 System.out.println(ASN1Dump.dumpAsString(var51));
                              }
                           } else {
                              EncryptedPrivateKeyInfo var54 = EncryptedPrivateKeyInfo.getInstance(var51.getBagValue());
                              PrivateKey var58 = this.unwrapKey(var54.getEncryptionAlgorithm(), var54.getEncryptedData(), var2, var11);
                              PKCS12BagAttributeCarrier var60 = (PKCS12BagAttributeCarrier)var58;
                              String var62 = null;
                              ASN1OctetString var63 = null;
                              if (var51.getBagAttributes() != null) {
                                 Enumeration var65 = var51.getBagAttributes().getObjects();

                                 while(var65.hasMoreElements()) {
                                    ASN1Sequence var67 = (ASN1Sequence)var65.nextElement();
                                    ASN1ObjectIdentifier var69 = (ASN1ObjectIdentifier)var67.getObjectAt(0);
                                    ASN1Set var70 = (ASN1Set)var67.getObjectAt(1);
                                    ASN1Primitive var71 = null;
                                    if (var70.size() > 0) {
                                       var71 = (ASN1Primitive)var70.getObjectAt(0);
                                       ASN1Encodable var72 = var60.getBagAttribute(var69);
                                       if (var72 != null) {
                                          if (!var72.toASN1Primitive().equals(var71)) {
                                             throw new IOException("attempt to add existing attribute with different value");
                                          }
                                       } else {
                                          var60.setBagAttribute(var69, var71);
                                       }
                                    }

                                    if (var69.equals(pkcs_9_at_friendlyName)) {
                                       var62 = ((DERBMPString)var71).getString();
                                       this.keys.put(var62, var58);
                                    } else if (var69.equals(pkcs_9_at_localKeyId)) {
                                       var63 = (ASN1OctetString)var71;
                                    }
                                 }
                              }

                              if (var63 != null) {
                                 String var66 = new String(Hex.encode(var63.getOctets()));
                                 if (var62 == null) {
                                    this.keys.put(var66, var58);
                                 } else {
                                    this.localIds.put(var62, var66);
                                 }
                              } else {
                                 var10 = true;
                                 this.keys.put("unmarked", var58);
                              }
                           }
                        }
                     } else if (!var36[var38].getContentType().equals(encryptedData)) {
                        System.out.println("extra " + var36[var38].getContentType().getId());
                        System.out.println("extra " + ASN1Dump.dumpAsString(var36[var38].getContent()));
                     } else {
                        EncryptedData var40 = EncryptedData.getInstance(var36[var38].getContent());
                        byte[] var43 = this.cryptData(false, var40.getEncryptionAlgorithm(), var2, var11, var40.getContent().getOctets());
                        ASN1Sequence var46 = (ASN1Sequence)ASN1Primitive.fromByteArray(var43);

                        for(int var50 = 0; var50 != var46.size(); ++var50) {
                           SafeBag var52 = SafeBag.getInstance(var46.getObjectAt(var50));
                           if (var52.getBagId().equals(certBag)) {
                              var9.addElement(var52);
                           } else {
                              PrivateKey var21;
                              String var23;
                              ASN1OctetString var24;
                              Enumeration var25;
                              ASN1Sequence var26;
                              ASN1ObjectIdentifier var27;
                              ASN1Set var28;
                              ASN1Primitive var29;
                              ASN1Encodable var30;
                              String var68;
                              if (var52.getBagId().equals(pkcs8ShroudedKeyBag)) {
                                 EncryptedPrivateKeyInfo var57 = EncryptedPrivateKeyInfo.getInstance(var52.getBagValue());
                                 var21 = this.unwrapKey(var57.getEncryptionAlgorithm(), var57.getEncryptedData(), var2, var11);
                                 var22 = (PKCS12BagAttributeCarrier)var21;
                                 var23 = null;
                                 var24 = null;
                                 var25 = var52.getBagAttributes().getObjects();

                                 while(var25.hasMoreElements()) {
                                    var26 = (ASN1Sequence)var25.nextElement();
                                    var27 = (ASN1ObjectIdentifier)var26.getObjectAt(0);
                                    var28 = (ASN1Set)var26.getObjectAt(1);
                                    var29 = null;
                                    if (var28.size() > 0) {
                                       var29 = (ASN1Primitive)var28.getObjectAt(0);
                                       var30 = var22.getBagAttribute(var27);
                                       if (var30 != null) {
                                          if (!var30.toASN1Primitive().equals(var29)) {
                                             throw new IOException("attempt to add existing attribute with different value");
                                          }
                                       } else {
                                          var22.setBagAttribute(var27, var29);
                                       }
                                    }

                                    if (var27.equals(pkcs_9_at_friendlyName)) {
                                       var23 = ((DERBMPString)var29).getString();
                                       this.keys.put(var23, var21);
                                    } else if (var27.equals(pkcs_9_at_localKeyId)) {
                                       var24 = (ASN1OctetString)var29;
                                    }
                                 }

                                 var68 = new String(Hex.encode(var24.getOctets()));
                                 if (var23 == null) {
                                    this.keys.put(var68, var21);
                                 } else {
                                    this.localIds.put(var23, var68);
                                 }
                              } else if (!var52.getBagId().equals(keyBag)) {
                                 System.out.println("extra in encryptedData " + var52.getBagId());
                                 System.out.println(ASN1Dump.dumpAsString(var52));
                              } else {
                                 PrivateKeyInfo var20 = new PrivateKeyInfo((ASN1Sequence)var52.getBagValue());
                                 var21 = BouncyCastleProvider.getPrivateKey(var20);
                                 var22 = (PKCS12BagAttributeCarrier)var21;
                                 var23 = null;
                                 var24 = null;
                                 var25 = var52.getBagAttributes().getObjects();

                                 while(var25.hasMoreElements()) {
                                    var26 = (ASN1Sequence)var25.nextElement();
                                    var27 = (ASN1ObjectIdentifier)var26.getObjectAt(0);
                                    var28 = (ASN1Set)var26.getObjectAt(1);
                                    var29 = null;
                                    if (var28.size() > 0) {
                                       var29 = (ASN1Primitive)var28.getObjectAt(0);
                                       var30 = var22.getBagAttribute(var27);
                                       if (var30 != null) {
                                          if (!var30.toASN1Primitive().equals(var29)) {
                                             throw new IOException("attempt to add existing attribute with different value");
                                          }
                                       } else {
                                          var22.setBagAttribute(var27, var29);
                                       }
                                    }

                                    if (var27.equals(pkcs_9_at_friendlyName)) {
                                       var23 = ((DERBMPString)var29).getString();
                                       this.keys.put(var23, var21);
                                    } else if (var27.equals(pkcs_9_at_localKeyId)) {
                                       var24 = (ASN1OctetString)var29;
                                    }
                                 }

                                 var68 = new String(Hex.encode(var24.getOctets()));
                                 if (var23 == null) {
                                    this.keys.put(var68, var21);
                                 } else {
                                    this.localIds.put(var23, var68);
                                 }
                              }
                           }
                        }
                     }
                  }
               }

               this.certs = new JDKPKCS12KeyStore.IgnoresCaseHashtable((JDKPKCS12KeyStore.IgnoresCaseHashtable)null);
               this.chainCerts = new Hashtable();
               this.keyCerts = new Hashtable();

               for(int var35 = 0; var35 != var9.size(); ++var35) {
                  SafeBag var37 = (SafeBag)var9.elementAt(var35);
                  CertBag var39 = CertBag.getInstance(var37.getBagValue());
                  if (!var39.getCertId().equals(x509Certificate)) {
                     throw new RuntimeException("Unsupported certificate type: " + var39.getCertId());
                  }

                  Certificate var42;
                  try {
                     ByteArrayInputStream var45 = new ByteArrayInputStream(((ASN1OctetString)var39.getCertValue()).getOctets());
                     var42 = this.certFact.generateCertificate(var45);
                  } catch (Exception var31) {
                     throw new RuntimeException(var31.toString());
                  }

                  ASN1OctetString var47 = null;
                  String var49 = null;
                  if (var37.getBagAttributes() != null) {
                     Enumeration var53 = var37.getBagAttributes().getObjects();

                     while(var53.hasMoreElements()) {
                        ASN1Sequence var55 = (ASN1Sequence)var53.nextElement();
                        ASN1ObjectIdentifier var59 = (ASN1ObjectIdentifier)var55.getObjectAt(0);
                        ASN1Primitive var61 = (ASN1Primitive)((ASN1Set)var55.getObjectAt(1)).getObjectAt(0);
                        var22 = null;
                        if (var42 instanceof PKCS12BagAttributeCarrier) {
                           var22 = (PKCS12BagAttributeCarrier)var42;
                           ASN1Encodable var64 = var22.getBagAttribute(var59);
                           if (var64 != null) {
                              if (!var64.toASN1Primitive().equals(var61)) {
                                 throw new IOException("attempt to add existing attribute with different value");
                              }
                           } else {
                              var22.setBagAttribute(var59, var61);
                           }
                        }

                        if (var59.equals(pkcs_9_at_friendlyName)) {
                           var49 = ((DERBMPString)var61).getString();
                        } else if (var59.equals(pkcs_9_at_localKeyId)) {
                           var47 = (ASN1OctetString)var61;
                        }
                     }
                  }

                  this.chainCerts.put(new JDKPKCS12KeyStore.CertId(var42.getPublicKey()), var42);
                  String var56;
                  if (var10) {
                     if (this.keyCerts.isEmpty()) {
                        var56 = new String(Hex.encode(this.createSubjectKeyId(var42.getPublicKey()).getKeyIdentifier()));
                        this.keyCerts.put(var56, var42);
                        this.keys.put(var56, this.keys.remove("unmarked"));
                     }
                  } else {
                     if (var47 != null) {
                        var56 = new String(Hex.encode(var47.getOctets()));
                        this.keyCerts.put(var56, var42);
                     }

                     if (var49 != null) {
                        this.certs.put(var49, var42);
                     }
                  }
               }

            }
         }
      }
   }

   public void engineStore(LoadStoreParameter var1) throws IOException, NoSuchAlgorithmException, CertificateException {
      if (var1 == null) {
         throw new IllegalArgumentException("'param' arg cannot be null");
      } else if (!(var1 instanceof JDKPKCS12StoreParameter)) {
         throw new IllegalArgumentException("No support for 'param' of type " + var1.getClass().getName());
      } else {
         JDKPKCS12StoreParameter var2 = (JDKPKCS12StoreParameter)var1;
         ProtectionParameter var4 = var1.getProtectionParameter();
         char[] var3;
         if (var4 == null) {
            var3 = null;
         } else {
            if (!(var4 instanceof PasswordProtection)) {
               throw new IllegalArgumentException("No support for protection parameter of type " + var4.getClass().getName());
            }

            var3 = ((PasswordProtection)var4).getPassword();
         }

         this.doStore(var2.getOutputStream(), var3, var2.isUseDEREncoding());
      }
   }

   public void engineStore(OutputStream var1, char[] var2) throws IOException {
      this.doStore(var1, var2, false);
   }

   private void doStore(OutputStream var1, char[] var2, boolean var3) throws IOException {
      if (var2 == null) {
         throw new NullPointerException("No password supplied for PKCS#12 KeyStore.");
      } else {
         ASN1EncodableVector var4 = new ASN1EncodableVector();
         Enumeration var5 = this.keys.keys();

         byte[] var6;
         AlgorithmIdentifier var11;
         ASN1EncodableVector var19;
         while(var5.hasMoreElements()) {
            var6 = new byte[20];
            this.random.nextBytes(var6);
            String var7 = (String)var5.nextElement();
            PrivateKey var8 = (PrivateKey)this.keys.get(var7);
            PKCS12PBEParams var9 = new PKCS12PBEParams(var6, 1024);
            byte[] var10 = this.wrapKey(this.keyAlgorithm.getId(), var8, var9, var2);
            var11 = new AlgorithmIdentifier(this.keyAlgorithm, var9.toASN1Primitive());
            EncryptedPrivateKeyInfo var12 = new EncryptedPrivateKeyInfo(var11, var10);
            boolean var13 = false;
            ASN1EncodableVector var14 = new ASN1EncodableVector();
            if (var8 instanceof PKCS12BagAttributeCarrier) {
               PKCS12BagAttributeCarrier var15 = (PKCS12BagAttributeCarrier)var8;
               DERBMPString var16 = (DERBMPString)var15.getBagAttribute(pkcs_9_at_friendlyName);
               if (var16 == null || !var16.getString().equals(var7)) {
                  var15.setBagAttribute(pkcs_9_at_friendlyName, new DERBMPString(var7));
               }

               if (var15.getBagAttribute(pkcs_9_at_localKeyId) == null) {
                  Certificate var17 = this.engineGetCertificate(var7);
                  var15.setBagAttribute(pkcs_9_at_localKeyId, this.createSubjectKeyId(var17.getPublicKey()));
               }

               Enumeration var48 = var15.getBagAttributeKeys();

               while(var48.hasMoreElements()) {
                  ASN1ObjectIdentifier var18 = (ASN1ObjectIdentifier)var48.nextElement();
                  var19 = new ASN1EncodableVector();
                  var19.add(var18);
                  var19.add(new DERSet(var15.getBagAttribute(var18)));
                  var13 = true;
                  var14.add(new DERSequence(var19));
               }
            }

            if (!var13) {
               ASN1EncodableVector var42 = new ASN1EncodableVector();
               Certificate var46 = this.engineGetCertificate(var7);
               var42.add(pkcs_9_at_localKeyId);
               var42.add(new DERSet(this.createSubjectKeyId(var46.getPublicKey())));
               var14.add(new DERSequence(var42));
               var42 = new ASN1EncodableVector();
               var42.add(pkcs_9_at_friendlyName);
               var42.add(new DERSet(new DERBMPString(var7)));
               var14.add(new DERSequence(var42));
            }

            SafeBag var44 = new SafeBag(pkcs8ShroudedKeyBag, var12.toASN1Primitive(), new DERSet(var14));
            var4.add(var44);
         }

         var6 = (new DERSequence(var4)).getEncoded("DER");
         BEROctetString var34 = new BEROctetString(var6);
         byte[] var35 = new byte[20];
         this.random.nextBytes(var35);
         ASN1EncodableVector var36 = new ASN1EncodableVector();
         PKCS12PBEParams var37 = new PKCS12PBEParams(var35, 1024);
         var11 = new AlgorithmIdentifier(this.certAlgorithm, var37.toASN1Primitive());
         Hashtable var38 = new Hashtable();
         Enumeration var39 = this.keys.keys();

         DERBMPString var20;
         Enumeration var21;
         ASN1ObjectIdentifier var22;
         ASN1EncodableVector var23;
         String var40;
         Certificate var45;
         boolean var47;
         CertBag var50;
         ASN1EncodableVector var52;
         PKCS12BagAttributeCarrier var57;
         SafeBag var60;
         while(var39.hasMoreElements()) {
            try {
               var40 = (String)var39.nextElement();
               var45 = this.engineGetCertificate(var40);
               var47 = false;
               var50 = new CertBag(x509Certificate, new DEROctetString(var45.getEncoded()));
               var52 = new ASN1EncodableVector();
               if (var45 instanceof PKCS12BagAttributeCarrier) {
                  var57 = (PKCS12BagAttributeCarrier)var45;
                  var20 = (DERBMPString)var57.getBagAttribute(pkcs_9_at_friendlyName);
                  if (var20 == null || !var20.getString().equals(var40)) {
                     var57.setBagAttribute(pkcs_9_at_friendlyName, new DERBMPString(var40));
                  }

                  if (var57.getBagAttribute(pkcs_9_at_localKeyId) == null) {
                     var57.setBagAttribute(pkcs_9_at_localKeyId, this.createSubjectKeyId(var45.getPublicKey()));
                  }

                  for(var21 = var57.getBagAttributeKeys(); var21.hasMoreElements(); var47 = true) {
                     var22 = (ASN1ObjectIdentifier)var21.nextElement();
                     var23 = new ASN1EncodableVector();
                     var23.add(var22);
                     var23.add(new DERSet(var57.getBagAttribute(var22)));
                     var52.add(new DERSequence(var23));
                  }
               }

               if (!var47) {
                  var19 = new ASN1EncodableVector();
                  var19.add(pkcs_9_at_localKeyId);
                  var19.add(new DERSet(this.createSubjectKeyId(var45.getPublicKey())));
                  var52.add(new DERSequence(var19));
                  var19 = new ASN1EncodableVector();
                  var19.add(pkcs_9_at_friendlyName);
                  var19.add(new DERSet(new DERBMPString(var40)));
                  var52.add(new DERSequence(var19));
               }

               var60 = new SafeBag(certBag, var50.toASN1Primitive(), new DERSet(var52));
               var36.add(var60);
               var38.put(var45, var45);
            } catch (CertificateEncodingException var33) {
               throw new IOException("Error encoding certificate: " + var33.toString());
            }
         }

         var39 = this.certs.keys();

         while(var39.hasMoreElements()) {
            try {
               var40 = (String)var39.nextElement();
               var45 = (Certificate)this.certs.get(var40);
               var47 = false;
               if (this.keys.get(var40) == null) {
                  var50 = new CertBag(x509Certificate, new DEROctetString(var45.getEncoded()));
                  var52 = new ASN1EncodableVector();
                  if (var45 instanceof PKCS12BagAttributeCarrier) {
                     var57 = (PKCS12BagAttributeCarrier)var45;
                     var20 = (DERBMPString)var57.getBagAttribute(pkcs_9_at_friendlyName);
                     if (var20 == null || !var20.getString().equals(var40)) {
                        var57.setBagAttribute(pkcs_9_at_friendlyName, new DERBMPString(var40));
                     }

                     var21 = var57.getBagAttributeKeys();

                     while(var21.hasMoreElements()) {
                        var22 = (ASN1ObjectIdentifier)var21.nextElement();
                        if (!var22.equals(PKCSObjectIdentifiers.pkcs_9_at_localKeyId)) {
                           var23 = new ASN1EncodableVector();
                           var23.add(var22);
                           var23.add(new DERSet(var57.getBagAttribute(var22)));
                           var52.add(new DERSequence(var23));
                           var47 = true;
                        }
                     }
                  }

                  if (!var47) {
                     var19 = new ASN1EncodableVector();
                     var19.add(pkcs_9_at_friendlyName);
                     var19.add(new DERSet(new DERBMPString(var40)));
                     var52.add(new DERSequence(var19));
                  }

                  var60 = new SafeBag(certBag, var50.toASN1Primitive(), new DERSet(var52));
                  var36.add(var60);
                  var38.put(var45, var45);
               }
            } catch (CertificateEncodingException var32) {
               throw new IOException("Error encoding certificate: " + var32.toString());
            }
         }

         var39 = this.chainCerts.keys();

         while(var39.hasMoreElements()) {
            try {
               JDKPKCS12KeyStore.CertId var41 = (JDKPKCS12KeyStore.CertId)var39.nextElement();
               var45 = (Certificate)this.chainCerts.get(var41);
               if (var38.get(var45) == null) {
                  CertBag var51 = new CertBag(x509Certificate, new DEROctetString(var45.getEncoded()));
                  ASN1EncodableVector var54 = new ASN1EncodableVector();
                  if (var45 instanceof PKCS12BagAttributeCarrier) {
                     PKCS12BagAttributeCarrier var56 = (PKCS12BagAttributeCarrier)var45;
                     Enumeration var63 = var56.getBagAttributeKeys();

                     while(var63.hasMoreElements()) {
                        ASN1ObjectIdentifier var61 = (ASN1ObjectIdentifier)var63.nextElement();
                        if (!var61.equals(PKCSObjectIdentifiers.pkcs_9_at_localKeyId)) {
                           ASN1EncodableVector var64 = new ASN1EncodableVector();
                           var64.add(var61);
                           var64.add(new DERSet(var56.getBagAttribute(var61)));
                           var54.add(new DERSequence(var64));
                        }
                     }
                  }

                  SafeBag var58 = new SafeBag(certBag, var51.toASN1Primitive(), new DERSet(var54));
                  var36.add(var58);
               }
            } catch (CertificateEncodingException var31) {
               throw new IOException("Error encoding certificate: " + var31.toString());
            }
         }

         byte[] var43 = (new DERSequence(var36)).getEncoded("DER");
         byte[] var49 = this.cryptData(true, var11, var2, false, var43);
         EncryptedData var53 = new EncryptedData(data, var11, new BEROctetString(var49));
         ContentInfo[] var55 = new ContentInfo[]{new ContentInfo(data, var34), new ContentInfo(encryptedData, var53.toASN1Primitive())};
         AuthenticatedSafe var59 = new AuthenticatedSafe(var55);
         ByteArrayOutputStream var65 = new ByteArrayOutputStream();
         Object var62;
         if (var3) {
            var62 = new DEROutputStream(var65);
         } else {
            var62 = new BEROutputStream(var65);
         }

         ((DEROutputStream)var62).writeObject(var59);
         byte[] var66 = var65.toByteArray();
         ContentInfo var67 = new ContentInfo(data, new BEROctetString(var66));
         byte[] var68 = new byte[20];
         short var24 = 1024;
         this.random.nextBytes(var68);
         byte[] var25 = ((ASN1OctetString)var67.getContent()).getOctets();

         MacData var26;
         try {
            byte[] var27 = calculatePbeMac(id_SHA1, var68, var24, var2, false, var25);
            AlgorithmIdentifier var28 = new AlgorithmIdentifier(id_SHA1, DERNull.INSTANCE);
            DigestInfo var29 = new DigestInfo(var28, var27);
            var26 = new MacData(var29, var68, var24);
         } catch (Exception var30) {
            throw new IOException("error constructing MAC: " + var30.toString());
         }

         Pfx var69 = new Pfx(var67, var26);
         if (var3) {
            var62 = new DEROutputStream(var1);
         } else {
            var62 = new BEROutputStream(var1);
         }

         ((DEROutputStream)var62).writeObject(var69);
      }
   }

   private static byte[] calculatePbeMac(ASN1ObjectIdentifier var0, byte[] var1, int var2, char[] var3, boolean var4, byte[] var5) throws Exception {
      SecretKeyFactory var6 = SecretKeyFactory.getInstance(var0.getId(), bcProvider);
      PBEParameterSpec var7 = new PBEParameterSpec(var1, var2);
      PBEKeySpec var8 = new PBEKeySpec(var3);
      BCPBEKey var9 = (BCPBEKey)var6.generateSecret(var8);
      var9.setTryWrongPKCS12Zero(var4);
      Mac var10 = Mac.getInstance(var0.getId(), bcProvider);
      var10.init(var9, var7);
      var10.update(var5);
      return var10.doFinal();
   }

   public static class BCPKCS12KeyStore extends JDKPKCS12KeyStore {
      public BCPKCS12KeyStore() {
         super(JDKPKCS12KeyStore.bcProvider, pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd40BitRC2_CBC);
      }
   }

   public static class BCPKCS12KeyStore3DES extends JDKPKCS12KeyStore {
      public BCPKCS12KeyStore3DES() {
         super(JDKPKCS12KeyStore.bcProvider, pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd3_KeyTripleDES_CBC);
      }
   }

   private class CertId {
      byte[] id;

      CertId(PublicKey var2) {
         this.id = JDKPKCS12KeyStore.this.createSubjectKeyId(var2).getKeyIdentifier();
      }

      CertId(byte[] var2) {
         this.id = var2;
      }

      public int hashCode() {
         return Arrays.hashCode(this.id);
      }

      public boolean equals(Object var1) {
         if (var1 == this) {
            return true;
         } else if (!(var1 instanceof JDKPKCS12KeyStore.CertId)) {
            return false;
         } else {
            JDKPKCS12KeyStore.CertId var2 = (JDKPKCS12KeyStore.CertId)var1;
            return Arrays.areEqual(this.id, var2.id);
         }
      }
   }

   public static class DefPKCS12KeyStore extends JDKPKCS12KeyStore {
      public DefPKCS12KeyStore() {
         super((Provider)null, pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd40BitRC2_CBC);
      }
   }

   public static class DefPKCS12KeyStore3DES extends JDKPKCS12KeyStore {
      public DefPKCS12KeyStore3DES() {
         super((Provider)null, pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd3_KeyTripleDES_CBC);
      }
   }

   private static class IgnoresCaseHashtable {
      private Hashtable orig;
      private Hashtable keys;

      private IgnoresCaseHashtable() {
         this.orig = new Hashtable();
         this.keys = new Hashtable();
      }

      public void put(String var1, Object var2) {
         String var3 = var1 == null ? null : Strings.toLowerCase(var1);
         String var4 = (String)this.keys.get(var3);
         if (var4 != null) {
            this.orig.remove(var4);
         }

         this.keys.put(var3, var1);
         this.orig.put(var1, var2);
      }

      public Enumeration keys() {
         return this.orig.keys();
      }

      public Object remove(String var1) {
         String var2 = (String)this.keys.remove(var1 == null ? null : Strings.toLowerCase(var1));
         return var2 == null ? null : this.orig.remove(var2);
      }

      public Object get(String var1) {
         String var2 = (String)this.keys.get(var1 == null ? null : Strings.toLowerCase(var1));
         return var2 == null ? null : this.orig.get(var2);
      }

      public Enumeration elements() {
         return this.orig.elements();
      }

      // $FF: synthetic method
      IgnoresCaseHashtable(JDKPKCS12KeyStore.IgnoresCaseHashtable var1) {
         this();
      }
   }
}
