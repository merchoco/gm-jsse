package cn.gmssl.com.sun.crypto.provider;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.DigestInputStream;
import java.security.DigestOutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import javax.crypto.SealedObject;

public final class JceKeyStore extends KeyStoreSpi {
   private static final int JCEKS_MAGIC = -825307442;
   private static final int JKS_MAGIC = -17957139;
   private static final int VERSION_1 = 1;
   private static final int VERSION_2 = 2;
   private Hashtable entries = new Hashtable();

   public Key engineGetKey(String var1, char[] var2) throws NoSuchAlgorithmException, UnrecoverableKeyException {
      Key var3 = null;
      Object var4 = this.entries.get(var1.toLowerCase());
      if (!(var4 instanceof JceKeyStore.PrivateKeyEntry) && !(var4 instanceof JceKeyStore.SecretKeyEntry)) {
         return null;
      } else {
         KeyProtector var5 = new KeyProtector(var2);
         if (var4 instanceof JceKeyStore.PrivateKeyEntry) {
            byte[] var6 = ((JceKeyStore.PrivateKeyEntry)var4).protectedKey;

            EncryptedPrivateKeyInfo var7;
            try {
               var7 = new EncryptedPrivateKeyInfo(var6);
            } catch (IOException var9) {
               throw new UnrecoverableKeyException("Private key not stored as PKCS #8 EncryptedPrivateKeyInfo");
            }

            var3 = var5.recover(var7);
         } else {
            var3 = var5.unseal(((JceKeyStore.SecretKeyEntry)var4).sealedKey);
         }

         return var3;
      }
   }

   public Certificate[] engineGetCertificateChain(String var1) {
      Certificate[] var2 = null;
      Object var3 = this.entries.get(var1.toLowerCase());
      if (var3 instanceof JceKeyStore.PrivateKeyEntry && ((JceKeyStore.PrivateKeyEntry)var3).chain != null) {
         var2 = (Certificate[])((JceKeyStore.PrivateKeyEntry)var3).chain.clone();
      }

      return var2;
   }

   public Certificate engineGetCertificate(String var1) {
      Certificate var2 = null;
      Object var3 = this.entries.get(var1.toLowerCase());
      if (var3 != null) {
         if (var3 instanceof JceKeyStore.TrustedCertEntry) {
            var2 = ((JceKeyStore.TrustedCertEntry)var3).cert;
         } else if (var3 instanceof JceKeyStore.PrivateKeyEntry && ((JceKeyStore.PrivateKeyEntry)var3).chain != null) {
            var2 = ((JceKeyStore.PrivateKeyEntry)var3).chain[0];
         }
      }

      return var2;
   }

   public Date engineGetCreationDate(String var1) {
      Date var2 = null;
      Object var3 = this.entries.get(var1.toLowerCase());
      if (var3 != null) {
         if (var3 instanceof JceKeyStore.TrustedCertEntry) {
            var2 = new Date(((JceKeyStore.TrustedCertEntry)var3).date.getTime());
         } else if (var3 instanceof JceKeyStore.PrivateKeyEntry) {
            var2 = new Date(((JceKeyStore.PrivateKeyEntry)var3).date.getTime());
         } else {
            var2 = new Date(((JceKeyStore.SecretKeyEntry)var3).date.getTime());
         }
      }

      return var2;
   }

   public void engineSetKeyEntry(String var1, Key var2, char[] var3, Certificate[] var4) throws KeyStoreException {
      Hashtable var5 = this.entries;
      synchronized(this.entries) {
         try {
            KeyProtector var6 = new KeyProtector(var3);
            if (var2 instanceof PrivateKey) {
               JceKeyStore.PrivateKeyEntry var7 = new JceKeyStore.PrivateKeyEntry((JceKeyStore.PrivateKeyEntry)null);
               var7.date = new Date();
               var7.protectedKey = var6.protect((PrivateKey)var2);
               if (var4 != null && var4.length != 0) {
                  var7.chain = (Certificate[])var4.clone();
               } else {
                  var7.chain = null;
               }

               this.entries.put(var1.toLowerCase(), var7);
            } else {
               JceKeyStore.SecretKeyEntry var10 = new JceKeyStore.SecretKeyEntry((JceKeyStore.SecretKeyEntry)null);
               var10.date = new Date();
               var10.sealedKey = var6.seal(var2);
               this.entries.put(var1.toLowerCase(), var10);
            }
         } catch (Exception var8) {
            throw new KeyStoreException(var8.getMessage());
         }

      }
   }

   public void engineSetKeyEntry(String var1, byte[] var2, Certificate[] var3) throws KeyStoreException {
      Hashtable var4 = this.entries;
      synchronized(this.entries) {
         JceKeyStore.PrivateKeyEntry var5 = new JceKeyStore.PrivateKeyEntry((JceKeyStore.PrivateKeyEntry)null);
         var5.date = new Date();
         var5.protectedKey = (byte[])var2.clone();
         if (var3 != null && var3.length != 0) {
            var5.chain = (Certificate[])var3.clone();
         } else {
            var5.chain = null;
         }

         this.entries.put(var1.toLowerCase(), var5);
      }
   }

   public void engineSetCertificateEntry(String var1, Certificate var2) throws KeyStoreException {
      Hashtable var3 = this.entries;
      synchronized(this.entries) {
         Object var4 = this.entries.get(var1.toLowerCase());
         if (var4 != null) {
            if (var4 instanceof JceKeyStore.PrivateKeyEntry) {
               throw new KeyStoreException("Cannot overwrite own certificate");
            }

            if (var4 instanceof JceKeyStore.SecretKeyEntry) {
               throw new KeyStoreException("Cannot overwrite secret key");
            }
         }

         JceKeyStore.TrustedCertEntry var5 = new JceKeyStore.TrustedCertEntry((JceKeyStore.TrustedCertEntry)null);
         var5.cert = var2;
         var5.date = new Date();
         this.entries.put(var1.toLowerCase(), var5);
      }
   }

   public void engineDeleteEntry(String var1) throws KeyStoreException {
      Hashtable var2 = this.entries;
      synchronized(this.entries) {
         this.entries.remove(var1.toLowerCase());
      }
   }

   public Enumeration engineAliases() {
      return this.entries.keys();
   }

   public boolean engineContainsAlias(String var1) {
      return this.entries.containsKey(var1.toLowerCase());
   }

   public int engineSize() {
      return this.entries.size();
   }

   public boolean engineIsKeyEntry(String var1) {
      boolean var2 = false;
      Object var3 = this.entries.get(var1.toLowerCase());
      if (var3 instanceof JceKeyStore.PrivateKeyEntry || var3 instanceof JceKeyStore.SecretKeyEntry) {
         var2 = true;
      }

      return var2;
   }

   public boolean engineIsCertificateEntry(String var1) {
      boolean var2 = false;
      Object var3 = this.entries.get(var1.toLowerCase());
      if (var3 instanceof JceKeyStore.TrustedCertEntry) {
         var2 = true;
      }

      return var2;
   }

   public String engineGetCertificateAlias(Certificate var1) {
      Enumeration var3 = this.entries.keys();

      Certificate var2;
      String var4;
      label26:
      do {
         Object var5;
         do {
            if (!var3.hasMoreElements()) {
               return null;
            }

            var4 = (String)var3.nextElement();
            var5 = this.entries.get(var4);
            if (var5 instanceof JceKeyStore.TrustedCertEntry) {
               var2 = ((JceKeyStore.TrustedCertEntry)var5).cert;
               continue label26;
            }
         } while(!(var5 instanceof JceKeyStore.PrivateKeyEntry) || ((JceKeyStore.PrivateKeyEntry)var5).chain == null);

         var2 = ((JceKeyStore.PrivateKeyEntry)var5).chain[0];
      } while(!var2.equals(var1));

      return var4;
   }

   public void engineStore(OutputStream var1, char[] var2) throws IOException, NoSuchAlgorithmException, CertificateException {
      Hashtable var3 = this.entries;
      synchronized(this.entries) {
         if (var2 == null) {
            throw new IllegalArgumentException("password can't be null");
         } else {
            MessageDigest var5 = this.getPreKeyedHash(var2);
            DataOutputStream var6 = new DataOutputStream(new DigestOutputStream(var1, var5));
            ObjectOutputStream var7 = null;

            try {
               var6.writeInt(-825307442);
               var6.writeInt(2);
               var6.writeInt(this.entries.size());
               Enumeration var8 = this.entries.keys();

               while(true) {
                  while(var8.hasMoreElements()) {
                     String var9 = (String)var8.nextElement();
                     Object var10 = this.entries.get(var9);
                     byte[] var4;
                     if (var10 instanceof JceKeyStore.PrivateKeyEntry) {
                        JceKeyStore.PrivateKeyEntry var11 = (JceKeyStore.PrivateKeyEntry)var10;
                        var6.writeInt(1);
                        var6.writeUTF(var9);
                        var6.writeLong(var11.date.getTime());
                        var6.writeInt(var11.protectedKey.length);
                        var6.write(var11.protectedKey);
                        int var12;
                        if (var11.chain == null) {
                           var12 = 0;
                        } else {
                           var12 = var11.chain.length;
                        }

                        var6.writeInt(var12);

                        for(int var13 = 0; var13 < var12; ++var13) {
                           var4 = var11.chain[var13].getEncoded();
                           var6.writeUTF(var11.chain[var13].getType());
                           var6.writeInt(var4.length);
                           var6.write(var4);
                        }
                     } else if (var10 instanceof JceKeyStore.TrustedCertEntry) {
                        var6.writeInt(2);
                        var6.writeUTF(var9);
                        var6.writeLong(((JceKeyStore.TrustedCertEntry)var10).date.getTime());
                        var4 = ((JceKeyStore.TrustedCertEntry)var10).cert.getEncoded();
                        var6.writeUTF(((JceKeyStore.TrustedCertEntry)var10).cert.getType());
                        var6.writeInt(var4.length);
                        var6.write(var4);
                     } else {
                        var6.writeInt(3);
                        var6.writeUTF(var9);
                        var6.writeLong(((JceKeyStore.SecretKeyEntry)var10).date.getTime());
                        var7 = new ObjectOutputStream(var6);
                        var7.writeObject(((JceKeyStore.SecretKeyEntry)var10).sealedKey);
                     }
                  }

                  byte[] var19 = var5.digest();
                  var6.write(var19);
                  var6.flush();
                  return;
               }
            } finally {
               if (var7 != null) {
                  var7.close();
               } else {
                  var6.close();
               }

            }
         }
      }
   }

   public void engineLoad(InputStream var1, char[] var2) throws IOException, NoSuchAlgorithmException, CertificateException {
      Hashtable var3 = this.entries;
      synchronized(this.entries) {
         MessageDigest var5 = null;
         CertificateFactory var6 = null;
         Hashtable var7 = null;
         ByteArrayInputStream var8 = null;
         Object var9 = null;
         if (var1 != null) {
            DataInputStream var4;
            if (var2 != null) {
               var5 = this.getPreKeyedHash(var2);
               var4 = new DataInputStream(new DigestInputStream(var1, var5));
            } else {
               var4 = new DataInputStream(var1);
            }

            ObjectInputStream var10 = null;

            try {
               int var11 = var4.readInt();
               int var12 = var4.readInt();
               if ((var11 == -825307442 || var11 == -17957139) && (var12 == 1 || var12 == 2)) {
                  if (var12 == 1) {
                     try {
                        var6 = CertificateFactory.getInstance("X509", "GMJCE");
                     } catch (NoSuchProviderException var34) {
                        throw new NoSuchAlgorithmException(var34.toString());
                     }
                  } else {
                     var7 = new Hashtable(3);
                  }

                  this.entries.clear();
                  int var13 = var4.readInt();

                  for(int var14 = 0; var14 < var13; ++var14) {
                     int var15 = var4.readInt();
                     String var16;
                     byte[] var38;
                     if (var15 == 1) {
                        JceKeyStore.PrivateKeyEntry var17 = new JceKeyStore.PrivateKeyEntry((JceKeyStore.PrivateKeyEntry)null);
                        var16 = var4.readUTF();
                        var17.date = new Date(var4.readLong());

                        try {
                           var17.protectedKey = new byte[var4.readInt()];
                        } catch (OutOfMemoryError var33) {
                           throw new IOException("Keysize too big");
                        }

                        var4.readFully(var17.protectedKey);
                        int var18 = var4.readInt();

                        try {
                           if (var18 > 0) {
                              var17.chain = new Certificate[var18];
                           }
                        } catch (OutOfMemoryError var35) {
                           throw new IOException("Too many certificates in chain");
                        }

                        for(int var19 = 0; var19 < var18; ++var19) {
                           if (var12 == 2) {
                              String var20 = var4.readUTF();
                              if (var7.containsKey(var20)) {
                                 var6 = (CertificateFactory)var7.get(var20);
                              } else {
                                 var6 = CertificateFactory.getInstance(var20);
                                 var7.put(var20, var6);
                              }
                           }

                           try {
                              var38 = new byte[var4.readInt()];
                           } catch (OutOfMemoryError var32) {
                              throw new IOException("Certificate too big");
                           }

                           var4.readFully(var38);
                           var8 = new ByteArrayInputStream(var38);
                           var17.chain[var19] = var6.generateCertificate(var8);
                        }

                        this.entries.put(var16, var17);
                     } else if (var15 == 2) {
                        JceKeyStore.TrustedCertEntry var42 = new JceKeyStore.TrustedCertEntry((JceKeyStore.TrustedCertEntry)null);
                        var16 = var4.readUTF();
                        var42.date = new Date(var4.readLong());
                        if (var12 == 2) {
                           String var44 = var4.readUTF();
                           if (var7.containsKey(var44)) {
                              var6 = (CertificateFactory)var7.get(var44);
                           } else {
                              var6 = CertificateFactory.getInstance(var44);
                              var7.put(var44, var6);
                           }
                        }

                        try {
                           var38 = new byte[var4.readInt()];
                        } catch (OutOfMemoryError var31) {
                           throw new IOException("Certificate too big");
                        }

                        var4.readFully(var38);
                        var8 = new ByteArrayInputStream(var38);
                        var42.cert = var6.generateCertificate(var8);
                        this.entries.put(var16, var42);
                     } else {
                        if (var15 != 3) {
                           throw new IOException("Unrecognized keystore entry");
                        }

                        JceKeyStore.SecretKeyEntry var43 = new JceKeyStore.SecretKeyEntry((JceKeyStore.SecretKeyEntry)null);
                        var16 = var4.readUTF();
                        var43.date = new Date(var4.readLong());

                        try {
                           var10 = new ObjectInputStream(var4);
                           var43.sealedKey = (SealedObject)var10.readObject();
                        } catch (ClassNotFoundException var30) {
                           throw new IOException(var30.getMessage());
                        }

                        this.entries.put(var16, var43);
                     }
                  }

                  if (var2 != null) {
                     byte[] var39 = var5.digest();
                     byte[] var40 = new byte[var39.length];
                     var4.readFully(var40);

                     for(int var41 = 0; var41 < var39.length; ++var41) {
                        if (var39[var41] != var40[var41]) {
                           throw new IOException("Keystore was tampered with, or password was incorrect");
                        }
                     }

                  }
               } else {
                  throw new IOException("Invalid keystore format");
               }
            } finally {
               if (var10 != null) {
                  var10.close();
               } else {
                  var4.close();
               }

            }
         }
      }
   }

   private MessageDigest getPreKeyedHash(char[] var1) throws NoSuchAlgorithmException, UnsupportedEncodingException {
      MessageDigest var4 = MessageDigest.getInstance("SHA");
      byte[] var5 = new byte[var1.length * 2];
      int var2 = 0;

      for(int var3 = 0; var2 < var1.length; ++var2) {
         var5[var3++] = (byte)(var1[var2] >> 8);
         var5[var3++] = (byte)var1[var2];
      }

      var4.update(var5);

      for(var2 = 0; var2 < var5.length; ++var2) {
         var5[var2] = 0;
      }

      var4.update("Mighty Aphrodite".getBytes("UTF8"));
      return var4;
   }

   private static final class PrivateKeyEntry {
      Date date;
      byte[] protectedKey;
      Certificate[] chain;

      private PrivateKeyEntry() {
      }

      // $FF: synthetic method
      PrivateKeyEntry(JceKeyStore.PrivateKeyEntry var1) {
         this();
      }
   }

   private static final class SecretKeyEntry {
      Date date;
      SealedObject sealedKey;

      private SecretKeyEntry() {
      }

      // $FF: synthetic method
      SecretKeyEntry(JceKeyStore.SecretKeyEntry var1) {
         this();
      }
   }

   private static final class TrustedCertEntry {
      Date date;
      Certificate cert;

      private TrustedCertEntry() {
      }

      // $FF: synthetic method
      TrustedCertEntry(JceKeyStore.TrustedCertEntry var1) {
         this();
      }
   }
}
