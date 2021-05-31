package org.bc.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.x500.X500Name;
import org.bc.crypto.prng.ThreadedSeedGenerator;
import org.bc.util.Arrays;
import org.bc.util.Integers;

public class TlsProtocolHandler {
   private static final Integer EXT_RenegotiationInfo = Integers.valueOf(65281);
   private static final short CS_CLIENT_HELLO_SEND = 1;
   private static final short CS_SERVER_HELLO_RECEIVED = 2;
   private static final short CS_SERVER_CERTIFICATE_RECEIVED = 3;
   private static final short CS_SERVER_KEY_EXCHANGE_RECEIVED = 4;
   private static final short CS_CERTIFICATE_REQUEST_RECEIVED = 5;
   private static final short CS_SERVER_HELLO_DONE_RECEIVED = 6;
   private static final short CS_CLIENT_KEY_EXCHANGE_SEND = 7;
   private static final short CS_CERTIFICATE_VERIFY_SEND = 8;
   private static final short CS_CLIENT_CHANGE_CIPHER_SPEC_SEND = 9;
   private static final short CS_CLIENT_FINISHED_SEND = 10;
   private static final short CS_SERVER_CHANGE_CIPHER_SPEC_RECEIVED = 11;
   private static final short CS_DONE = 12;
   private static final byte[] emptybuf = new byte[0];
   private static final String TLS_ERROR_MESSAGE = "Internal TLS error, this could be an attack";
   private ByteQueue applicationDataQueue;
   private ByteQueue changeCipherSpecQueue;
   private ByteQueue alertQueue;
   private ByteQueue handshakeQueue;
   private RecordStream rs;
   private SecureRandom random;
   private TlsInputStream tlsInputStream;
   private TlsOutputStream tlsOutputStream;
   private boolean closed;
   private boolean failedWithError;
   private boolean appDataReady;
   private Hashtable clientExtensions;
   private SecurityParameters securityParameters;
   private TlsClientContextImpl tlsClientContext;
   private TlsClient tlsClient;
   private int[] offeredCipherSuites;
   private short[] offeredCompressionMethods;
   private TlsKeyExchange keyExchange;
   private TlsAuthentication authentication;
   private CertificateRequest certificateRequest;
   private short connection_state;

   private static SecureRandom createSecureRandom() {
      ThreadedSeedGenerator var0 = new ThreadedSeedGenerator();
      SecureRandom var1 = new SecureRandom();
      var1.setSeed(var0.generateSeed(20, true));
      return var1;
   }

   public TlsProtocolHandler(InputStream var1, OutputStream var2) {
      this(var1, var2, createSecureRandom());
   }

   public TlsProtocolHandler(InputStream var1, OutputStream var2, SecureRandom var3) {
      this.applicationDataQueue = new ByteQueue();
      this.changeCipherSpecQueue = new ByteQueue();
      this.alertQueue = new ByteQueue();
      this.handshakeQueue = new ByteQueue();
      this.tlsInputStream = null;
      this.tlsOutputStream = null;
      this.closed = false;
      this.failedWithError = false;
      this.appDataReady = false;
      this.securityParameters = null;
      this.tlsClientContext = null;
      this.tlsClient = null;
      this.offeredCipherSuites = null;
      this.offeredCompressionMethods = null;
      this.keyExchange = null;
      this.authentication = null;
      this.certificateRequest = null;
      this.connection_state = 0;
      this.rs = new RecordStream(this, var1, var2);
      this.random = var3;
   }

   protected void processData(short var1, byte[] var2, int var3, int var4) throws IOException {
      switch(var1) {
      case 20:
         this.changeCipherSpecQueue.addData(var2, var3, var4);
         this.processChangeCipherSpec();
         break;
      case 21:
         this.alertQueue.addData(var2, var3, var4);
         this.processAlert();
         break;
      case 22:
         this.handshakeQueue.addData(var2, var3, var4);
         this.processHandshake();
         break;
      case 23:
         if (!this.appDataReady) {
            this.failWithError((short)2, (short)10);
         }

         this.applicationDataQueue.addData(var2, var3, var4);
         this.processApplicationData();
      }

   }

   private void processHandshake() throws IOException {
      boolean var1;
      do {
         var1 = false;
         if (this.handshakeQueue.size() >= 4) {
            byte[] var2 = new byte[4];
            this.handshakeQueue.read(var2, 0, 4, 0);
            ByteArrayInputStream var3 = new ByteArrayInputStream(var2);
            short var4 = TlsUtils.readUint8(var3);
            int var5 = TlsUtils.readUint24(var3);
            if (this.handshakeQueue.size() >= var5 + 4) {
               byte[] var6 = new byte[var5];
               this.handshakeQueue.read(var6, 0, var5, 4);
               this.handshakeQueue.removeData(var5 + 4);
               switch(var4) {
               default:
                  this.rs.updateHandshakeData(var2, 0, 4);
                  this.rs.updateHandshakeData(var6, 0, var5);
               case 0:
               case 20:
                  this.processHandshakeMessage(var4, var6);
                  var1 = true;
               }
            }
         }
      } while(var1);

   }

   private void processHandshakeMessage(short var1, byte[] var2) throws IOException {
      ByteArrayInputStream var3 = new ByteArrayInputStream(var2);
      byte[] var6;
      byte[] var7;
      byte[] var9;
      switch(var1) {
      case 0:
         if (this.connection_state == 12) {
            this.sendAlert((short)1, (short)100);
         }
         break;
      case 1:
      case 3:
      case 4:
      case 5:
      case 6:
      case 7:
      case 8:
      case 9:
      case 10:
      case 15:
      case 16:
      case 17:
      case 18:
      case 19:
      default:
         this.failWithError((short)2, (short)10);
         break;
      case 2:
         switch(this.connection_state) {
         case 1:
            ProtocolVersion var19 = TlsUtils.readVersion((InputStream)var3);
            ProtocolVersion var21 = this.tlsClientContext.getClientVersion();
            if (var19.getFullVersion() > var21.getFullVersion()) {
               this.failWithError((short)2, (short)47);
            }

            this.tlsClientContext.setServerVersion(var19);
            this.tlsClient.notifyServerVersion(var19);
            this.securityParameters.serverRandom = new byte[32];
            TlsUtils.readFully(this.securityParameters.serverRandom, var3);
            var6 = TlsUtils.readOpaque8(var3);
            if (var6.length > 32) {
               this.failWithError((short)2, (short)47);
            }

            this.tlsClient.notifySessionID(var6);
            int var25 = TlsUtils.readUint16(var3);
            if (!arrayContains(this.offeredCipherSuites, var25) || var25 == 255) {
               this.failWithError((short)2, (short)47);
            }

            this.tlsClient.notifySelectedCipherSuite(var25);
            short var28 = TlsUtils.readUint8(var3);
            if (!arrayContains(this.offeredCompressionMethods, var28)) {
               this.failWithError((short)2, (short)47);
            }

            this.tlsClient.notifySelectedCompressionMethod(var28);
            Hashtable var29 = new Hashtable();
            if (var3.available() > 0) {
               byte[] var10 = TlsUtils.readOpaque16(var3);

               Integer var12;
               byte[] var13;
               for(ByteArrayInputStream var11 = new ByteArrayInputStream(var10); var11.available() > 0; var29.put(var12, var13)) {
                  var12 = Integers.valueOf(TlsUtils.readUint16(var11));
                  var13 = TlsUtils.readOpaque16(var11);
                  if (!var12.equals(EXT_RenegotiationInfo) && this.clientExtensions.get(var12) == null) {
                     this.failWithError((short)2, (short)110);
                  }

                  if (var29.containsKey(var12)) {
                     this.failWithError((short)2, (short)47);
                  }
               }
            }

            this.assertEmpty(var3);
            boolean var30 = var29.containsKey(EXT_RenegotiationInfo);
            if (var30) {
               byte[] var31 = (byte[])var29.get(EXT_RenegotiationInfo);
               if (!Arrays.constantTimeAreEqual(var31, createRenegotiationInfo(emptybuf))) {
                  this.failWithError((short)2, (short)40);
               }
            }

            this.tlsClient.notifySecureRenegotiation(var30);
            if (this.clientExtensions != null) {
               this.tlsClient.processServerExtensions(var29);
            }

            this.keyExchange = this.tlsClient.getKeyExchange();
            this.connection_state = 2;
            return;
         default:
            this.failWithError((short)2, (short)10);
            return;
         }
      case 11:
         switch(this.connection_state) {
         case 2:
            Certificate var17 = Certificate.parse(var3);
            this.assertEmpty(var3);
            this.keyExchange.processServerCertificate(var17);
            this.authentication = this.tlsClient.getAuthentication();
            this.authentication.notifyServerCertificate(var17);
            break;
         default:
            this.failWithError((short)2, (short)10);
         }

         this.connection_state = 3;
         break;
      case 12:
         switch(this.connection_state) {
         case 2:
            this.keyExchange.skipServerCertificate();
            this.authentication = null;
         case 3:
            this.keyExchange.processServerKeyExchange(var3);
            this.assertEmpty(var3);
            break;
         default:
            this.failWithError((short)2, (short)10);
         }

         this.connection_state = 4;
         break;
      case 13:
         switch(this.connection_state) {
         case 3:
            this.keyExchange.skipServerKeyExchange();
         case 4:
            if (this.authentication == null) {
               this.failWithError((short)2, (short)40);
            }

            short var15 = TlsUtils.readUint8(var3);
            short[] var20 = new short[var15];

            for(int var23 = 0; var23 < var15; ++var23) {
               var20[var23] = TlsUtils.readUint8(var3);
            }

            var6 = TlsUtils.readOpaque16(var3);
            this.assertEmpty(var3);
            Vector var24 = new Vector();
            ByteArrayInputStream var27 = new ByteArrayInputStream(var6);

            while(var27.available() > 0) {
               var9 = TlsUtils.readOpaque16(var27);
               var24.addElement(X500Name.getInstance(ASN1Primitive.fromByteArray(var9)));
            }

            this.certificateRequest = new CertificateRequest(var20, var24);
            this.keyExchange.validateCertificateRequest(this.certificateRequest);
            break;
         default:
            this.failWithError((short)2, (short)10);
         }

         this.connection_state = 5;
         break;
      case 14:
         switch(this.connection_state) {
         case 2:
            this.keyExchange.skipServerCertificate();
            this.authentication = null;
         case 3:
            this.keyExchange.skipServerKeyExchange();
         case 4:
         case 5:
            this.assertEmpty(var3);
            this.connection_state = 6;
            TlsCredentials var14 = null;
            if (this.certificateRequest == null) {
               this.keyExchange.skipClientCredentials();
            } else {
               var14 = this.authentication.getClientCredentials(this.certificateRequest);
               if (var14 == null) {
                  this.keyExchange.skipClientCredentials();
                  boolean var16 = this.tlsClientContext.getServerVersion().getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();
                  if (var16) {
                     this.sendClientCertificate(Certificate.EMPTY_CHAIN);
                  } else {
                     this.sendAlert((short)1, (short)41);
                  }
               } else {
                  this.keyExchange.processClientCredentials(var14);
                  this.sendClientCertificate(var14.getCertificate());
               }
            }

            this.sendClientKeyExchange();
            this.connection_state = 7;
            byte[] var18 = this.keyExchange.generatePremasterSecret();
            this.securityParameters.masterSecret = TlsUtils.calculateMasterSecret(this.tlsClientContext, var18);
            Arrays.fill((byte[])var18, (byte)0);
            if (var14 != null && var14 instanceof TlsSignerCredentials) {
               TlsSignerCredentials var22 = (TlsSignerCredentials)var14;
               var7 = this.rs.getCurrentHash((byte[])null);
               byte[] var8 = var22.generateCertificateSignature(var7);
               this.sendCertificateVerify(var8);
               this.connection_state = 8;
            }

            var6 = new byte[]{1};
            this.rs.writeMessage((short)20, var6, 0, var6.length);
            this.connection_state = 9;
            this.rs.clientCipherSpecDecided(this.tlsClient.getCompression(), this.tlsClient.getCipher());
            var7 = TlsUtils.calculateVerifyData(this.tlsClientContext, "client finished", this.rs.getCurrentHash(TlsUtils.SSL_CLIENT));
            ByteArrayOutputStream var26 = new ByteArrayOutputStream();
            TlsUtils.writeUint8((short)20, var26);
            TlsUtils.writeOpaque24(var7, var26);
            var9 = var26.toByteArray();
            this.rs.writeMessage((short)22, var9, 0, var9.length);
            this.connection_state = 10;
            return;
         default:
            this.failWithError((short)2, (short)40);
            return;
         }
      case 20:
         switch(this.connection_state) {
         case 11:
            boolean var4 = this.tlsClientContext.getServerVersion().getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();
            int var5 = var4 ? 12 : 36;
            var6 = new byte[var5];
            TlsUtils.readFully(var6, var3);
            this.assertEmpty(var3);
            var7 = TlsUtils.calculateVerifyData(this.tlsClientContext, "server finished", this.rs.getCurrentHash(TlsUtils.SSL_SERVER));
            if (!Arrays.constantTimeAreEqual(var7, var6)) {
               this.failWithError((short)2, (short)40);
            }

            this.connection_state = 12;
            this.appDataReady = true;
            break;
         default:
            this.failWithError((short)2, (short)10);
         }
      }

   }

   private void processApplicationData() {
   }

   private void processAlert() throws IOException {
      while(this.alertQueue.size() >= 2) {
         byte[] var1 = new byte[2];
         this.alertQueue.read(var1, 0, 2, 0);
         this.alertQueue.removeData(2);
         byte var2 = var1[0];
         byte var3 = var1[1];
         if (var2 == 2) {
            this.failedWithError = true;
            this.closed = true;

            try {
               this.rs.close();
            } catch (Exception var5) {
               ;
            }

            throw new IOException("Internal TLS error, this could be an attack");
         }

         if (var3 == 0) {
            this.failWithError((short)1, (short)0);
         }
      }

   }

   private void processChangeCipherSpec() throws IOException {
      while(this.changeCipherSpecQueue.size() > 0) {
         byte[] var1 = new byte[1];
         this.changeCipherSpecQueue.read(var1, 0, 1, 0);
         this.changeCipherSpecQueue.removeData(1);
         if (var1[0] != 1) {
            this.failWithError((short)2, (short)10);
         }

         if (this.connection_state != 10) {
            this.failWithError((short)2, (short)40);
         }

         this.rs.serverClientSpecReceived();
         this.connection_state = 11;
      }

   }

   private void sendClientCertificate(Certificate var1) throws IOException {
      ByteArrayOutputStream var2 = new ByteArrayOutputStream();
      TlsUtils.writeUint8((short)11, var2);
      TlsUtils.writeUint24(0, var2);
      var1.encode(var2);
      byte[] var3 = var2.toByteArray();
      TlsUtils.writeUint24(var3.length - 4, var3, 1);
      this.rs.writeMessage((short)22, var3, 0, var3.length);
   }

   private void sendClientKeyExchange() throws IOException {
      ByteArrayOutputStream var1 = new ByteArrayOutputStream();
      TlsUtils.writeUint8((short)16, var1);
      TlsUtils.writeUint24(0, var1);
      this.keyExchange.generateClientKeyExchange(var1);
      byte[] var2 = var1.toByteArray();
      TlsUtils.writeUint24(var2.length - 4, var2, 1);
      this.rs.writeMessage((short)22, var2, 0, var2.length);
   }

   private void sendCertificateVerify(byte[] var1) throws IOException {
      ByteArrayOutputStream var2 = new ByteArrayOutputStream();
      TlsUtils.writeUint8((short)15, var2);
      TlsUtils.writeUint24(var1.length + 2, var2);
      TlsUtils.writeOpaque16(var1, var2);
      byte[] var3 = var2.toByteArray();
      this.rs.writeMessage((short)22, var3, 0, var3.length);
   }

   /** @deprecated */
   public void connect(CertificateVerifyer var1) throws IOException {
      this.connect((TlsClient)(new LegacyTlsClient(var1)));
   }

   public void connect(TlsClient var1) throws IOException {
      if (var1 == null) {
         throw new IllegalArgumentException("'tlsClient' cannot be null");
      } else if (this.tlsClient != null) {
         throw new IllegalStateException("connect can only be called once");
      } else {
         this.securityParameters = new SecurityParameters();
         this.securityParameters.clientRandom = new byte[32];
         this.random.nextBytes(this.securityParameters.clientRandom);
         TlsUtils.writeGMTUnixTime(this.securityParameters.clientRandom, 0);
         this.tlsClientContext = new TlsClientContextImpl(this.random, this.securityParameters);
         this.rs.init(this.tlsClientContext);
         this.tlsClient = var1;
         this.tlsClient.init(this.tlsClientContext);
         ByteArrayOutputStream var2 = new ByteArrayOutputStream();
         ProtocolVersion var3 = this.tlsClient.getClientVersion();
         this.tlsClientContext.setClientVersion(var3);
         this.tlsClientContext.setServerVersion(var3);
         TlsUtils.writeVersion(var3, var2);
         var2.write(this.securityParameters.clientRandom);
         TlsUtils.writeUint8((short)0, var2);
         this.offeredCipherSuites = this.tlsClient.getCipherSuites();
         this.clientExtensions = this.tlsClient.getClientExtensions();
         boolean var4 = this.clientExtensions == null || this.clientExtensions.get(EXT_RenegotiationInfo) == null;
         int var5 = this.offeredCipherSuites.length;
         if (var4) {
            ++var5;
         }

         TlsUtils.writeUint16(2 * var5, var2);
         TlsUtils.writeUint16Array(this.offeredCipherSuites, var2);
         if (var4) {
            TlsUtils.writeUint16(255, var2);
         }

         this.offeredCompressionMethods = this.tlsClient.getCompressionMethods();
         TlsUtils.writeUint8((short)this.offeredCompressionMethods.length, var2);
         TlsUtils.writeUint8Array(this.offeredCompressionMethods, var2);
         ByteArrayOutputStream var7;
         if (this.clientExtensions != null) {
            var7 = new ByteArrayOutputStream();
            Enumeration var8 = this.clientExtensions.keys();

            while(var8.hasMoreElements()) {
               Integer var6 = (Integer)var8.nextElement();
               writeExtension(var7, var6, (byte[])this.clientExtensions.get(var6));
            }

            TlsUtils.writeOpaque16(var7.toByteArray(), var2);
         }

         var7 = new ByteArrayOutputStream();
         TlsUtils.writeUint8((short)1, var7);
         TlsUtils.writeUint24(var2.size(), var7);
         var7.write(var2.toByteArray());
         byte[] var9 = var7.toByteArray();
         this.safeWriteMessage((short)22, var9, 0, var9.length);
         this.connection_state = 1;

         while(this.connection_state != 12) {
            this.safeReadData();
         }

         this.tlsInputStream = new TlsInputStream(this);
         this.tlsOutputStream = new TlsOutputStream(this);
      }
   }

   protected int readApplicationData(byte[] var1, int var2, int var3) throws IOException {
      while(this.applicationDataQueue.size() == 0) {
         if (this.closed) {
            if (this.failedWithError) {
               throw new IOException("Internal TLS error, this could be an attack");
            }

            return -1;
         }

         this.safeReadData();
      }

      var3 = Math.min(var3, this.applicationDataQueue.size());
      this.applicationDataQueue.read(var1, var2, var3, 0);
      this.applicationDataQueue.removeData(var3);
      return var3;
   }

   private void safeReadData() throws IOException {
      try {
         this.rs.readData();
      } catch (TlsFatalAlert var2) {
         if (!this.closed) {
            this.failWithError((short)2, var2.getAlertDescription());
         }

         throw var2;
      } catch (IOException var3) {
         if (!this.closed) {
            this.failWithError((short)2, (short)80);
         }

         throw var3;
      } catch (RuntimeException var4) {
         if (!this.closed) {
            this.failWithError((short)2, (short)80);
         }

         throw var4;
      }
   }

   private void safeWriteMessage(short var1, byte[] var2, int var3, int var4) throws IOException {
      try {
         this.rs.writeMessage(var1, var2, var3, var4);
      } catch (TlsFatalAlert var6) {
         if (!this.closed) {
            this.failWithError((short)2, var6.getAlertDescription());
         }

         throw var6;
      } catch (IOException var7) {
         if (!this.closed) {
            this.failWithError((short)2, (short)80);
         }

         throw var7;
      } catch (RuntimeException var8) {
         if (!this.closed) {
            this.failWithError((short)2, (short)80);
         }

         throw var8;
      }
   }

   protected void writeData(byte[] var1, int var2, int var3) throws IOException {
      if (this.closed) {
         if (this.failedWithError) {
            throw new IOException("Internal TLS error, this could be an attack");
         } else {
            throw new IOException("Sorry, connection has been closed, you cannot write more data");
         }
      } else {
         this.safeWriteMessage((short)23, emptybuf, 0, 0);

         do {
            int var4 = Math.min(var3, 16384);
            this.safeWriteMessage((short)23, var1, var2, var4);
            var2 += var4;
            var3 -= var4;
         } while(var3 > 0);

      }
   }

   public OutputStream getOutputStream() {
      return this.tlsOutputStream;
   }

   public InputStream getInputStream() {
      return this.tlsInputStream;
   }

   private void failWithError(short var1, short var2) throws IOException {
      if (!this.closed) {
         this.closed = true;
         if (var1 == 2) {
            this.failedWithError = true;
         }

         this.sendAlert(var1, var2);
         this.rs.close();
         if (var1 == 2) {
            throw new IOException("Internal TLS error, this could be an attack");
         }
      } else {
         throw new IOException("Internal TLS error, this could be an attack");
      }
   }

   private void sendAlert(short var1, short var2) throws IOException {
      byte[] var3 = new byte[]{(byte)var1, (byte)var2};
      this.rs.writeMessage((short)21, var3, 0, 2);
   }

   public void close() throws IOException {
      if (!this.closed) {
         this.failWithError((short)1, (short)0);
      }

   }

   protected void assertEmpty(ByteArrayInputStream var1) throws IOException {
      if (var1.available() > 0) {
         throw new TlsFatalAlert((short)50);
      }
   }

   protected void flush() throws IOException {
      this.rs.flush();
   }

   private static boolean arrayContains(short[] var0, short var1) {
      for(int var2 = 0; var2 < var0.length; ++var2) {
         if (var0[var2] == var1) {
            return true;
         }
      }

      return false;
   }

   private static boolean arrayContains(int[] var0, int var1) {
      for(int var2 = 0; var2 < var0.length; ++var2) {
         if (var0[var2] == var1) {
            return true;
         }
      }

      return false;
   }

   private static byte[] createRenegotiationInfo(byte[] var0) throws IOException {
      ByteArrayOutputStream var1 = new ByteArrayOutputStream();
      TlsUtils.writeOpaque8(var0, var1);
      return var1.toByteArray();
   }

   private static void writeExtension(OutputStream var0, Integer var1, byte[] var2) throws IOException {
      TlsUtils.writeUint16(var1, var0);
      TlsUtils.writeOpaque16(var2, var0);
   }
}
