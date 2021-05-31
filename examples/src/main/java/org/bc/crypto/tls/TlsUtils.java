package org.bc.crypto.tls;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.bc.asn1.x509.Extension;
import org.bc.asn1.x509.Extensions;
import org.bc.asn1.x509.KeyUsage;
import org.bc.asn1.x509.X509Extension;
import org.bc.crypto.Digest;
import org.bc.crypto.digests.MD5Digest;
import org.bc.crypto.digests.SHA1Digest;
import org.bc.crypto.macs.HMac;
import org.bc.crypto.params.KeyParameter;
import org.bc.util.Arrays;
import org.bc.util.Strings;
import org.bc.util.io.Streams;

public class TlsUtils {
   static final byte[] SSL_CLIENT = new byte[]{67, 76, 78, 84};
   static final byte[] SSL_SERVER = new byte[]{83, 82, 86, 82};
   static final byte[][] SSL3_CONST = genConst();

   protected static void writeUint8(short var0, OutputStream var1) throws IOException {
      var1.write(var0);
   }

   protected static void writeUint8(short var0, byte[] var1, int var2) {
      var1[var2] = (byte)var0;
   }

   protected static void writeUint16(int var0, OutputStream var1) throws IOException {
      var1.write(var0 >> 8);
      var1.write(var0);
   }

   protected static void writeUint16(int var0, byte[] var1, int var2) {
      var1[var2] = (byte)(var0 >> 8);
      var1[var2 + 1] = (byte)var0;
   }

   protected static void writeUint24(int var0, OutputStream var1) throws IOException {
      var1.write(var0 >> 16);
      var1.write(var0 >> 8);
      var1.write(var0);
   }

   protected static void writeUint24(int var0, byte[] var1, int var2) {
      var1[var2] = (byte)(var0 >> 16);
      var1[var2 + 1] = (byte)(var0 >> 8);
      var1[var2 + 2] = (byte)var0;
   }

   protected static void writeUint32(long var0, OutputStream var2) throws IOException {
      var2.write((int)(var0 >> 24));
      var2.write((int)(var0 >> 16));
      var2.write((int)(var0 >> 8));
      var2.write((int)var0);
   }

   protected static void writeUint32(long var0, byte[] var2, int var3) {
      var2[var3] = (byte)((int)(var0 >> 24));
      var2[var3 + 1] = (byte)((int)(var0 >> 16));
      var2[var3 + 2] = (byte)((int)(var0 >> 8));
      var2[var3 + 3] = (byte)((int)var0);
   }

   protected static void writeUint64(long var0, OutputStream var2) throws IOException {
      var2.write((int)(var0 >> 56));
      var2.write((int)(var0 >> 48));
      var2.write((int)(var0 >> 40));
      var2.write((int)(var0 >> 32));
      var2.write((int)(var0 >> 24));
      var2.write((int)(var0 >> 16));
      var2.write((int)(var0 >> 8));
      var2.write((int)var0);
   }

   protected static void writeUint64(long var0, byte[] var2, int var3) {
      var2[var3] = (byte)((int)(var0 >> 56));
      var2[var3 + 1] = (byte)((int)(var0 >> 48));
      var2[var3 + 2] = (byte)((int)(var0 >> 40));
      var2[var3 + 3] = (byte)((int)(var0 >> 32));
      var2[var3 + 4] = (byte)((int)(var0 >> 24));
      var2[var3 + 5] = (byte)((int)(var0 >> 16));
      var2[var3 + 6] = (byte)((int)(var0 >> 8));
      var2[var3 + 7] = (byte)((int)var0);
   }

   protected static void writeOpaque8(byte[] var0, OutputStream var1) throws IOException {
      writeUint8((short)var0.length, var1);
      var1.write(var0);
   }

   protected static void writeOpaque16(byte[] var0, OutputStream var1) throws IOException {
      writeUint16(var0.length, var1);
      var1.write(var0);
   }

   protected static void writeOpaque24(byte[] var0, OutputStream var1) throws IOException {
      writeUint24(var0.length, var1);
      var1.write(var0);
   }

   protected static void writeUint8Array(short[] var0, OutputStream var1) throws IOException {
      for(int var2 = 0; var2 < var0.length; ++var2) {
         writeUint8(var0[var2], var1);
      }

   }

   protected static void writeUint16Array(int[] var0, OutputStream var1) throws IOException {
      for(int var2 = 0; var2 < var0.length; ++var2) {
         writeUint16(var0[var2], var1);
      }

   }

   protected static short readUint8(InputStream var0) throws IOException {
      int var1 = var0.read();
      if (var1 == -1) {
         throw new EOFException();
      } else {
         return (short)var1;
      }
   }

   protected static int readUint16(InputStream var0) throws IOException {
      int var1 = var0.read();
      int var2 = var0.read();
      if ((var1 | var2) < 0) {
         throw new EOFException();
      } else {
         return var1 << 8 | var2;
      }
   }

   protected static int readUint24(InputStream var0) throws IOException {
      int var1 = var0.read();
      int var2 = var0.read();
      int var3 = var0.read();
      if ((var1 | var2 | var3) < 0) {
         throw new EOFException();
      } else {
         return var1 << 16 | var2 << 8 | var3;
      }
   }

   protected static long readUint32(InputStream var0) throws IOException {
      int var1 = var0.read();
      int var2 = var0.read();
      int var3 = var0.read();
      int var4 = var0.read();
      if ((var1 | var2 | var3 | var4) < 0) {
         throw new EOFException();
      } else {
         return (long)var1 << 24 | (long)var2 << 16 | (long)var3 << 8 | (long)var4;
      }
   }

   protected static void readFully(byte[] var0, InputStream var1) throws IOException {
      if (Streams.readFully(var1, var0) != var0.length) {
         throw new EOFException();
      }
   }

   protected static byte[] readOpaque8(InputStream var0) throws IOException {
      short var1 = readUint8(var0);
      byte[] var2 = new byte[var1];
      readFully(var2, var0);
      return var2;
   }

   protected static byte[] readOpaque16(InputStream var0) throws IOException {
      int var1 = readUint16(var0);
      byte[] var2 = new byte[var1];
      readFully(var2, var0);
      return var2;
   }

   static ProtocolVersion readVersion(byte[] var0) throws IOException {
      return ProtocolVersion.get(var0[0], var0[1]);
   }

   static ProtocolVersion readVersion(InputStream var0) throws IOException {
      int var1 = var0.read();
      int var2 = var0.read();
      return ProtocolVersion.get(var1, var2);
   }

   protected static void writeGMTUnixTime(byte[] var0, int var1) {
      int var2 = (int)(System.currentTimeMillis() / 1000L);
      var0[var1] = (byte)(var2 >> 24);
      var0[var1 + 1] = (byte)(var2 >> 16);
      var0[var1 + 2] = (byte)(var2 >> 8);
      var0[var1 + 3] = (byte)var2;
   }

   static void writeVersion(ProtocolVersion var0, OutputStream var1) throws IOException {
      var1.write(var0.getMajorVersion());
      var1.write(var0.getMinorVersion());
   }

   static void writeVersion(ProtocolVersion var0, byte[] var1, int var2) throws IOException {
      var1[var2] = (byte)var0.getMajorVersion();
      var1[var2 + 1] = (byte)var0.getMinorVersion();
   }

   private static void hmac_hash(Digest var0, byte[] var1, byte[] var2, byte[] var3) {
      HMac var4 = new HMac(var0);
      KeyParameter var5 = new KeyParameter(var1);
      byte[] var6 = var2;
      int var7 = var0.getDigestSize();
      int var8 = (var3.length + var7 - 1) / var7;
      byte[] var9 = new byte[var4.getMacSize()];
      byte[] var10 = new byte[var4.getMacSize()];

      for(int var11 = 0; var11 < var8; ++var11) {
         var4.init(var5);
         var4.update(var6, 0, var6.length);
         var4.doFinal(var9, 0);
         var6 = var9;
         var4.init(var5);
         var4.update(var9, 0, var9.length);
         var4.update(var2, 0, var2.length);
         var4.doFinal(var10, 0);
         System.arraycopy(var10, 0, var3, var7 * var11, Math.min(var7, var3.length - var7 * var11));
      }

   }

   protected static byte[] PRF(byte[] var0, String var1, byte[] var2, int var3) {
      byte[] var4 = Strings.toByteArray(var1);
      int var5 = (var0.length + 1) / 2;
      byte[] var6 = new byte[var5];
      byte[] var7 = new byte[var5];
      System.arraycopy(var0, 0, var6, 0, var5);
      System.arraycopy(var0, var0.length - var5, var7, 0, var5);
      byte[] var8 = concat(var4, var2);
      byte[] var9 = new byte[var3];
      byte[] var10 = new byte[var3];
      hmac_hash(new MD5Digest(), var6, var8, var10);
      hmac_hash(new SHA1Digest(), var7, var8, var9);

      for(int var11 = 0; var11 < var3; ++var11) {
         var9[var11] ^= var10[var11];
      }

      return var9;
   }

   static byte[] PRF_1_2(Digest var0, byte[] var1, String var2, byte[] var3, int var4) {
      byte[] var5 = Strings.toByteArray(var2);
      byte[] var6 = concat(var5, var3);
      byte[] var7 = new byte[var4];
      hmac_hash(var0, var1, var6, var7);
      return var7;
   }

   static byte[] concat(byte[] var0, byte[] var1) {
      byte[] var2 = new byte[var0.length + var1.length];
      System.arraycopy(var0, 0, var2, 0, var0.length);
      System.arraycopy(var1, 0, var2, var0.length, var1.length);
      return var2;
   }

   static void validateKeyUsage(org.bc.asn1.x509.Certificate var0, int var1) throws IOException {
      Extensions var2 = var0.getTBSCertificate().getExtensions();
      if (var2 != null) {
         Extension var3 = var2.getExtension(X509Extension.keyUsage);
         if (var3 != null) {
            KeyUsage var4 = KeyUsage.getInstance(var3);
            int var5 = var4.getBytes()[0] & 255;
            if ((var5 & var1) != var1) {
               throw new TlsFatalAlert((short)46);
            }
         }
      }

   }

   static byte[] calculateKeyBlock(TlsClientContext var0, int var1) {
      ProtocolVersion var2 = var0.getServerVersion();
      SecurityParameters var3 = var0.getSecurityParameters();
      byte[] var4 = concat(var3.serverRandom, var3.clientRandom);
      boolean var5 = var2.getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();
      if (var5) {
         return PRF(var3.masterSecret, "key expansion", var4, var1);
      } else {
         MD5Digest var6 = new MD5Digest();
         SHA1Digest var7 = new SHA1Digest();
         int var8 = var6.getDigestSize();
         byte[] var9 = new byte[var7.getDigestSize()];
         byte[] var10 = new byte[var1 + var8];
         int var11 = 0;

         byte[] var13;
         for(int var12 = 0; var12 < var1; ++var11) {
            var13 = SSL3_CONST[var11];
            var7.update(var13, 0, var13.length);
            var7.update(var3.masterSecret, 0, var3.masterSecret.length);
            var7.update(var4, 0, var4.length);
            var7.doFinal(var9, 0);
            var6.update(var3.masterSecret, 0, var3.masterSecret.length);
            var6.update(var9, 0, var9.length);
            var6.doFinal(var10, var12);
            var12 += var8;
         }

         var13 = new byte[var1];
         System.arraycopy(var10, 0, var13, 0, var1);
         return var13;
      }
   }

   static byte[] calculateMasterSecret(TlsClientContext var0, byte[] var1) {
      ProtocolVersion var2 = var0.getServerVersion();
      SecurityParameters var3 = var0.getSecurityParameters();
      byte[] var4 = concat(var3.clientRandom, var3.serverRandom);
      boolean var5 = var2.getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();
      if (var5) {
         return PRF(var1, "master secret", var4, 48);
      } else {
         MD5Digest var6 = new MD5Digest();
         SHA1Digest var7 = new SHA1Digest();
         int var8 = var6.getDigestSize();
         byte[] var9 = new byte[var7.getDigestSize()];
         byte[] var10 = new byte[var8 * 3];
         int var11 = 0;

         for(int var12 = 0; var12 < 3; ++var12) {
            byte[] var13 = SSL3_CONST[var12];
            var7.update(var13, 0, var13.length);
            var7.update(var1, 0, var1.length);
            var7.update(var4, 0, var4.length);
            var7.doFinal(var9, 0);
            var6.update(var1, 0, var1.length);
            var6.update(var9, 0, var9.length);
            var6.doFinal(var10, var11);
            var11 += var8;
         }

         return var10;
      }
   }

   static byte[] calculateVerifyData(TlsClientContext var0, String var1, byte[] var2) {
      ProtocolVersion var3 = var0.getServerVersion();
      SecurityParameters var4 = var0.getSecurityParameters();
      boolean var5 = var3.getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();
      return var5 ? PRF(var4.masterSecret, var1, var2, 12) : var2;
   }

   private static byte[][] genConst() {
      byte var0 = 10;
      byte[][] var1 = new byte[var0][];

      for(int var2 = 0; var2 < var0; ++var2) {
         byte[] var3 = new byte[var2 + 1];
         Arrays.fill(var3, (byte)(65 + var2));
         var1[var2] = var3;
      }

      return var1;
   }
}
