package cn.gmssl.com.sun.crypto.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyRep;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.KeyRep.Type;
import java.util.Arrays;
import javax.crypto.spec.DHParameterSpec;
import sun.security.util.Debug;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;

final class DHPrivateKey implements PrivateKey, javax.crypto.interfaces.DHPrivateKey, Serializable {
   static final long serialVersionUID = 7565477590005668886L;
   private static final BigInteger PKCS8_VERSION;
   private BigInteger x;
   private byte[] key;
   private byte[] encodedKey;
   private BigInteger p;
   private BigInteger g;
   private int l;
   private int[] DH_data;

   static {
      PKCS8_VERSION = BigInteger.ZERO;
   }

   DHPrivateKey(BigInteger var1, BigInteger var2, BigInteger var3) throws InvalidKeyException {
      this(var1, var2, var3, 0);
   }

   DHPrivateKey(BigInteger var1, BigInteger var2, BigInteger var3, int var4) {
      this.DH_data = new int[]{1, 2, 840, 113549, 1, 3, 1};
      this.x = var1;
      this.p = var2;
      this.g = var3;
      this.l = var4;

      try {
         this.key = (new DerValue((byte)2, this.x.toByteArray())).toByteArray();
         this.encodedKey = this.getEncoded();
      } catch (IOException var6) {
         throw new ProviderException("Cannot produce ASN.1 encoding", var6);
      }
   }

   DHPrivateKey(byte[] var1) throws InvalidKeyException {
      this.DH_data = new int[]{1, 2, 840, 113549, 1, 3, 1};
      ByteArrayInputStream var2 = new ByteArrayInputStream(var1);

      InvalidKeyException var4;
      try {
         DerValue var3 = new DerValue(var2);
         if (var3.tag != 48) {
            throw new InvalidKeyException("Key not a SEQUENCE");
         } else {
            BigInteger var11 = var3.data.getBigInteger();
            if (!var11.equals(PKCS8_VERSION)) {
               throw new IOException("version mismatch: (supported: " + PKCS8_VERSION + ", parsed: " + var11);
            } else {
               DerValue var5 = var3.data.getDerValue();
               if (var5.tag != 48) {
                  throw new InvalidKeyException("AlgId is not a SEQUENCE");
               } else {
                  DerInputStream var6 = var5.toDerInputStream();
                  ObjectIdentifier var7 = var6.getOID();
                  if (var7 == null) {
                     throw new InvalidKeyException("Null OID");
                  } else if (var6.available() == 0) {
                     throw new InvalidKeyException("Parameters missing");
                  } else {
                     DerValue var8 = var6.getDerValue();
                     if (var8.tag == 5) {
                        throw new InvalidKeyException("Null parameters");
                     } else if (var8.tag != 48) {
                        throw new InvalidKeyException("Parameters not a SEQUENCE");
                     } else {
                        var8.data.reset();
                        this.p = var8.data.getBigInteger();
                        this.g = var8.data.getBigInteger();
                        if (var8.data.available() != 0) {
                           this.l = var8.data.getInteger();
                        }

                        if (var8.data.available() != 0) {
                           throw new InvalidKeyException("Extra parameter data");
                        } else {
                           this.key = var3.data.getOctetString();
                           this.parseKeyBits();
                           this.encodedKey = (byte[])var1.clone();
                        }
                     }
                  }
               }
            }
         }
      } catch (NumberFormatException var9) {
         var4 = new InvalidKeyException("Private-value length too big");
         var4.initCause(var9);
         throw var4;
      } catch (IOException var10) {
         var4 = new InvalidKeyException("Error parsing key encoding: " + var10.getMessage());
         var4.initCause(var10);
         throw var4;
      }
   }

   public String getFormat() {
      return "PKCS#8";
   }

   public String getAlgorithm() {
      return "DH";
   }

   public synchronized byte[] getEncoded() {
      if (this.encodedKey == null) {
         try {
            DerOutputStream var1 = new DerOutputStream();
            var1.putInteger(PKCS8_VERSION);
            DerOutputStream var2 = new DerOutputStream();
            var2.putOID(new ObjectIdentifier(this.DH_data));
            DerOutputStream var3 = new DerOutputStream();
            var3.putInteger(this.p);
            var3.putInteger(this.g);
            if (this.l != 0) {
               var3.putInteger(this.l);
            }

            DerValue var4 = new DerValue((byte)48, var3.toByteArray());
            var3.close();
            var2.putDerValue(var4);
            var1.write((byte)48, var2);
            var1.putOctetString(this.key);
            DerOutputStream var5 = new DerOutputStream();
            var5.write((byte)48, var1);
            this.encodedKey = var5.toByteArray();
            var5.close();
         } catch (IOException var6) {
            return null;
         }
      }

      return (byte[])this.encodedKey.clone();
   }

   public BigInteger getX() {
      return this.x;
   }

   public DHParameterSpec getParams() {
      return this.l != 0 ? new DHParameterSpec(this.p, this.g, this.l) : new DHParameterSpec(this.p, this.g);
   }

   public String toString() {
      String var1 = System.getProperty("line.separator");
      StringBuffer var2 = new StringBuffer("SunJCE Diffie-Hellman Private Key:" + var1 + "x:" + var1 + Debug.toHexString(this.x) + var1 + "p:" + var1 + Debug.toHexString(this.p) + var1 + "g:" + var1 + Debug.toHexString(this.g));
      if (this.l != 0) {
         var2.append(var1 + "l:" + var1 + "    " + this.l);
      }

      return var2.toString();
   }

   private void parseKeyBits() throws InvalidKeyException {
      try {
         DerInputStream var1 = new DerInputStream(this.key);
         this.x = var1.getBigInteger();
      } catch (IOException var3) {
         InvalidKeyException var2 = new InvalidKeyException("Error parsing key encoding: " + var3.getMessage());
         var2.initCause(var3);
         throw var2;
      }
   }

   public int hashCode() {
      int var1 = 0;
      byte[] var2 = this.getEncoded();

      for(int var3 = 1; var3 < var2.length; ++var3) {
         var1 += var2[var3] * var3;
      }

      return var1;
   }

   public boolean equals(Object var1) {
      if (this == var1) {
         return true;
      } else if (!(var1 instanceof PrivateKey)) {
         return false;
      } else {
         byte[] var2 = this.getEncoded();
         byte[] var3 = ((PrivateKey)var1).getEncoded();
         return Arrays.equals(var2, var3);
      }
   }

   private Object writeReplace() throws ObjectStreamException {
      return new KeyRep(Type.PRIVATE, this.getAlgorithm(), this.getFormat(), this.getEncoded());
   }
}
