package cn.gmssl.com.sun.crypto.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyRep;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.KeyRep.Type;
import java.util.Arrays;
import javax.crypto.spec.DHParameterSpec;
import sun.security.util.Debug;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;

final class DHPublicKey implements PublicKey, javax.crypto.interfaces.DHPublicKey, Serializable {
   static final long serialVersionUID = 7647557958927458271L;
   private BigInteger y;
   private byte[] key;
   private byte[] encodedKey;
   private BigInteger p;
   private BigInteger g;
   private int l;
   private int[] DH_data;

   DHPublicKey(BigInteger var1, BigInteger var2, BigInteger var3) throws InvalidKeyException {
      this(var1, var2, var3, 0);
   }

   DHPublicKey(BigInteger var1, BigInteger var2, BigInteger var3, int var4) {
      this.DH_data = new int[]{1, 2, 840, 113549, 1, 3, 1};
      this.y = var1;
      this.p = var2;
      this.g = var3;
      this.l = var4;

      try {
         this.key = (new DerValue((byte)2, this.y.toByteArray())).toByteArray();
         this.encodedKey = this.getEncoded();
      } catch (IOException var6) {
         throw new ProviderException("Cannot produce ASN.1 encoding", var6);
      }
   }

   DHPublicKey(byte[] var1) throws InvalidKeyException {
      this.DH_data = new int[]{1, 2, 840, 113549, 1, 3, 1};
      ByteArrayInputStream var2 = new ByteArrayInputStream(var1);

      try {
         DerValue var3 = new DerValue(var2);
         if (var3.tag != 48) {
            throw new InvalidKeyException("Invalid key format");
         } else {
            DerValue var4 = var3.data.getDerValue();
            if (var4.tag != 48) {
               throw new InvalidKeyException("AlgId is not a SEQUENCE");
            } else {
               DerInputStream var5 = var4.toDerInputStream();
               ObjectIdentifier var6 = var5.getOID();
               if (var6 == null) {
                  throw new InvalidKeyException("Null OID");
               } else if (var5.available() == 0) {
                  throw new InvalidKeyException("Parameters missing");
               } else {
                  DerValue var7 = var5.getDerValue();
                  if (var7.tag == 5) {
                     throw new InvalidKeyException("Null parameters");
                  } else if (var7.tag != 48) {
                     throw new InvalidKeyException("Parameters not a SEQUENCE");
                  } else {
                     var7.data.reset();
                     this.p = var7.data.getBigInteger();
                     this.g = var7.data.getBigInteger();
                     if (var7.data.available() != 0) {
                        this.l = var7.data.getInteger();
                     }

                     if (var7.data.available() != 0) {
                        throw new InvalidKeyException("Extra parameter data");
                     } else {
                        this.key = var3.data.getBitString();
                        this.parseKeyBits();
                        if (var3.data.available() != 0) {
                           throw new InvalidKeyException("Excess key data");
                        } else {
                           this.encodedKey = (byte[])var1.clone();
                        }
                     }
                  }
               }
            }
         }
      } catch (NumberFormatException var8) {
         throw new InvalidKeyException("Private-value length too big");
      } catch (IOException var9) {
         throw new InvalidKeyException("Error parsing key encoding: " + var9.toString());
      }
   }

   public String getFormat() {
      return "X.509";
   }

   public String getAlgorithm() {
      return "DH";
   }

   public synchronized byte[] getEncoded() {
      if (this.encodedKey == null) {
         try {
            DerOutputStream var1 = new DerOutputStream();
            var1.putOID(new ObjectIdentifier(this.DH_data));
            DerOutputStream var2 = new DerOutputStream();
            var2.putInteger(this.p);
            var2.putInteger(this.g);
            if (this.l != 0) {
               var2.putInteger(this.l);
            }

            DerValue var3 = new DerValue((byte)48, var2.toByteArray());
            var2.close();
            var1.putDerValue(var3);
            DerOutputStream var4 = new DerOutputStream();
            var4.write((byte)48, var1);
            var4.putBitString(this.key);
            DerOutputStream var5 = new DerOutputStream();
            var5.write((byte)48, var4);
            this.encodedKey = var5.toByteArray();
            var5.close();
         } catch (IOException var6) {
            return null;
         }
      }

      return (byte[])this.encodedKey.clone();
   }

   public BigInteger getY() {
      return this.y;
   }

   public DHParameterSpec getParams() {
      return this.l != 0 ? new DHParameterSpec(this.p, this.g, this.l) : new DHParameterSpec(this.p, this.g);
   }

   public String toString() {
      String var1 = System.getProperty("line.separator");
      StringBuffer var2 = new StringBuffer("SunJCE Diffie-Hellman Public Key:" + var1 + "y:" + var1 + Debug.toHexString(this.y) + var1 + "p:" + var1 + Debug.toHexString(this.p) + var1 + "g:" + var1 + Debug.toHexString(this.g));
      if (this.l != 0) {
         var2.append(var1 + "l:" + var1 + "    " + this.l);
      }

      return var2.toString();
   }

   private void parseKeyBits() throws InvalidKeyException {
      try {
         DerInputStream var1 = new DerInputStream(this.key);
         this.y = var1.getBigInteger();
      } catch (IOException var2) {
         throw new InvalidKeyException("Error parsing key encoding: " + var2.toString());
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
      } else if (!(var1 instanceof PublicKey)) {
         return false;
      } else {
         byte[] var2 = this.getEncoded();
         byte[] var3 = ((PublicKey)var1).getEncoded();
         return Arrays.equals(var2, var3);
      }
   }

   private Object writeReplace() throws ObjectStreamException {
      return new KeyRep(Type.PUBLIC, this.getAlgorithm(), this.getFormat(), this.getEncoded());
   }
}
