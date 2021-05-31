package cn.gmssl.sun.security.ssl;

import cn.gmssl.jsse.provider.GMConf;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.AlgorithmConstraints;
import java.security.GeneralSecurityException;
import javax.crypto.BadPaddingException;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;

public final class SSLEngineImpl extends SSLEngine {
   private int connectionState;
   private static final int cs_START = 0;
   private static final int cs_HANDSHAKE = 1;
   private static final int cs_DATA = 2;
   private static final int cs_RENEGOTIATE = 3;
   private static final int cs_ERROR = 4;
   private static final int cs_CLOSED = 6;
   private boolean inboundDone = false;
   EngineWriter writer;
   private SSLContextImpl sslContext;
   private Handshaker handshaker;
   private SSLSessionImpl sess;
   private volatile SSLSessionImpl handshakeSession;
   static final byte clauth_none = 0;
   static final byte clauth_requested = 1;
   static final byte clauth_required = 2;
   private boolean expectingFinished;
   private boolean recvCN;
   private SSLException closeReason;
   private byte doClientAuth;
   private boolean enableSessionCreation = true;
   EngineInputRecord inputRecord;
   EngineOutputRecord outputRecord;
   private AccessControlContext acc;
   private CipherSuiteList enabledCipherSuites;
   private String identificationProtocol = null;
   private AlgorithmConstraints algorithmConstraints = null;
   private boolean serverModeSet = false;
   private boolean roleIsServer;
   private ProtocolList enabledProtocols;
   private ProtocolVersion protocolVersion;
   private MAC readMAC;
   private MAC writeMAC;
   private CipherBox readCipher;
   private CipherBox writeCipher;
   private boolean secureRenegotiation;
   private byte[] clientVerifyData;
   private byte[] serverVerifyData;
   private Object wrapLock;
   private Object unwrapLock;
   Object writeLock;
   private static final Debug debug = Debug.getInstance("ssl");

   SSLEngineImpl(SSLContextImpl var1) {
      this.protocolVersion = ProtocolVersion.DEFAULT;
      this.init(var1);
   }

   SSLEngineImpl(SSLContextImpl var1, String var2, int var3) {
      super(var2, var3);
      this.protocolVersion = ProtocolVersion.DEFAULT;
      this.init(var1);
   }

   private void init(SSLContextImpl var1) {
      if (debug != null && Debug.isOn("ssl")) {
         System.out.println("Using SSLEngineImpl.");
      }

      this.sslContext = var1;
      this.sess = SSLSessionImpl.nullSession;
      this.handshakeSession = null;
      this.roleIsServer = true;
      this.connectionState = 0;
      this.readCipher = CipherBox.NULL;
      this.readMAC = MAC.NULL;
      this.writeCipher = CipherBox.NULL;
      this.writeMAC = MAC.NULL;
      this.secureRenegotiation = false;
      this.clientVerifyData = new byte[0];
      this.serverVerifyData = new byte[0];
      this.enabledCipherSuites = this.sslContext.getDefaultCipherSuiteList(this.roleIsServer);
      this.enabledProtocols = this.sslContext.getDefaultProtocolList(this.roleIsServer);
      this.wrapLock = new Object();
      this.unwrapLock = new Object();
      this.writeLock = new Object();
      this.acc = AccessController.getContext();
      this.outputRecord = new EngineOutputRecord((byte)23, this);
      this.inputRecord = new EngineInputRecord(this);
      this.inputRecord.enableFormatChecks();
      this.writer = new EngineWriter();
   }

   private void initHandshaker() {
      switch(this.connectionState) {
      case 0:
      case 2:
         if (this.connectionState == 0) {
            this.connectionState = 1;
         } else {
            this.connectionState = 3;
         }

         if (this.roleIsServer) {
            this.handshaker = new ServerHandshaker(this, this.sslContext, this.enabledProtocols, this.doClientAuth, this.protocolVersion, this.connectionState == 1, this.secureRenegotiation, this.clientVerifyData, this.serverVerifyData);
         } else {
            this.handshaker = new ClientHandshaker(this, this.sslContext, this.enabledProtocols, this.protocolVersion, this.connectionState == 1, this.secureRenegotiation, this.clientVerifyData, this.serverVerifyData);
         }

         if (GMConf.debug) {
            System.out.println("SSLEngineImpl setEnabledCipherSuites=" + this.enabledCipherSuites);
         }

         this.handshaker.setEnabledCipherSuites(this.enabledCipherSuites);
         this.handshaker.setEnableSessionCreation(this.enableSessionCreation);
         return;
      case 1:
      case 3:
         return;
      default:
         throw new IllegalStateException("Internal error");
      }
   }

   private HandshakeStatus getHSStatus(HandshakeStatus var1) {
      if (var1 != null) {
         return var1;
      } else {
         synchronized(this) {
            if (this.writer.hasOutboundData()) {
               return HandshakeStatus.NEED_WRAP;
            } else if (this.handshaker != null) {
               return this.handshaker.taskOutstanding() ? HandshakeStatus.NEED_TASK : HandshakeStatus.NEED_UNWRAP;
            } else {
               return this.connectionState == 6 && !this.isInboundDone() ? HandshakeStatus.NEED_UNWRAP : HandshakeStatus.NOT_HANDSHAKING;
            }
         }
      }
   }

   private synchronized void checkTaskThrown() throws SSLException {
      if (this.handshaker != null) {
         this.handshaker.checkThrown();
      }

   }

   private synchronized int getConnectionState() {
      return this.connectionState;
   }

   private synchronized void setConnectionState(int var1) {
      this.connectionState = var1;
   }

   AccessControlContext getAcc() {
      return this.acc;
   }

   public HandshakeStatus getHandshakeStatus() {
      return this.getHSStatus((HandshakeStatus)null);
   }

   private void changeReadCiphers() throws SSLException {
      if (this.connectionState != 1 && this.connectionState != 3) {
         throw new SSLProtocolException("State error, change cipher specs");
      } else {
         CipherBox var1 = this.readCipher;

         try {
            this.readCipher = this.handshaker.newReadCipher();
            this.readMAC = this.handshaker.newReadMAC();
         } catch (GeneralSecurityException var3) {
            throw (SSLException)(new SSLException("Algorithm missing:  ")).initCause(var3);
         }

         var1.dispose();
      }
   }

   void changeWriteCiphers() throws SSLException {
      if (this.connectionState != 1 && this.connectionState != 3) {
         throw new SSLProtocolException("State error, change cipher specs");
      } else {
         CipherBox var1 = this.writeCipher;

         try {
            this.writeCipher = this.handshaker.newWriteCipher();
            this.writeMAC = this.handshaker.newWriteMAC();
         } catch (GeneralSecurityException var3) {
            throw (SSLException)(new SSLException("Algorithm missing:  ")).initCause(var3);
         }

         var1.dispose();
      }
   }

   synchronized void setVersion(ProtocolVersion var1) {
      this.protocolVersion = var1;
      this.outputRecord.setVersion(var1);
   }

   private synchronized void kickstartHandshake() throws IOException {
      switch(this.connectionState) {
      case 0:
         if (!this.serverModeSet) {
            throw new IllegalStateException("Client/Server mode not yet set.");
         }

         this.initHandshaker();
      case 1:
         break;
      case 2:
         if (!this.secureRenegotiation && !Handshaker.allowUnsafeRenegotiation) {
            throw new SSLHandshakeException("Insecure renegotiation is not allowed");
         }

         if (!this.secureRenegotiation && debug != null && Debug.isOn("handshake")) {
            System.out.println("Warning: Using insecure renegotiation");
         }

         this.initHandshaker();
         break;
      case 3:
         return;
      default:
         throw new SSLException("SSLEngine is closing/closed");
      }

      if (!this.handshaker.activated()) {
         if (this.connectionState == 3) {
            this.handshaker.activate(this.protocolVersion);
         } else {
            this.handshaker.activate((ProtocolVersion)null);
         }

         if (this.handshaker instanceof ClientHandshaker) {
            this.handshaker.kickstart();
         } else if (this.connectionState != 1) {
            this.handshaker.kickstart();
            this.handshaker.handshakeHash.reset();
         }
      }

   }

   public void beginHandshake() throws SSLException {
      try {
         this.kickstartHandshake();
      } catch (Exception var2) {
         this.fatal((byte)40, "Couldn't kickstart handshaking", var2);
      }

   }

   public SSLEngineResult unwrap(ByteBuffer var1, ByteBuffer[] var2, int var3, int var4) throws SSLException {
      EngineArgs var5 = new EngineArgs(var1, var2, var3, var4);

      try {
         Object var6 = this.unwrapLock;
         synchronized(this.unwrapLock) {
            SSLEngineResult var8 = this.readNetRecord(var5);
            return var8;
         }
      } catch (Exception var13) {
         this.fatal((byte)80, "problem unwrapping net record", var13);
      } finally {
         var5.resetLim();
      }

      return null;
   }

   private SSLEngineResult readNetRecord(EngineArgs var1) throws IOException {
      Status var2 = null;
      HandshakeStatus var3 = null;
      this.checkTaskThrown();
      if (this.isInboundDone()) {
         return new SSLEngineResult(Status.CLOSED, this.getHSStatus((HandshakeStatus)null), 0, 0);
      } else {
         synchronized(this) {
            if (this.connectionState == 1 || this.connectionState == 0) {
               this.kickstartHandshake();
               var3 = this.getHSStatus((HandshakeStatus)null);
               if (var3 == HandshakeStatus.NEED_WRAP) {
                  return new SSLEngineResult(Status.OK, var3, 0, 0);
               }
            }
         }

         if (var3 == null) {
            var3 = this.getHSStatus((HandshakeStatus)null);
         }

         if (var3 == HandshakeStatus.NEED_TASK) {
            return new SSLEngineResult(Status.OK, var3, 0, 0);
         } else {
            int var4 = this.inputRecord.bytesInCompletePacket(var1.netData);
            if (var4 > this.sess.getPacketBufferSize()) {
               if (var4 > 33305) {
                  throw new SSLProtocolException("Input SSL/TLS record too big: max = 33305 len = " + var4);
               }

               this.sess.expandBufferSizes();
            }

            if (var4 - 5 > var1.getAppRemaining()) {
               return new SSLEngineResult(Status.BUFFER_OVERFLOW, var3, 0, 0);
            } else if (var4 != -1 && var1.netData.remaining() >= var4) {
               try {
                  var3 = this.readRecord(var1);
               } catch (SSLException var7) {
                  throw var7;
               } catch (IOException var8) {
                  SSLException var6 = new SSLException("readRecord");
                  var6.initCause(var8);
                  throw var6;
               }

               var2 = this.isInboundDone() ? Status.CLOSED : Status.OK;
               var3 = this.getHSStatus(var3);
               return new SSLEngineResult(var2, var3, var1.deltaNet(), var1.deltaApp());
            } else {
               return new SSLEngineResult(Status.BUFFER_UNDERFLOW, var3, 0, 0);
            }
         }
      }
   }

   private HandshakeStatus readRecord(EngineArgs var1) throws IOException {
      HandshakeStatus var2 = null;
      ByteBuffer var3 = null;
      ByteBuffer var4 = null;
      if (this.getConnectionState() != 4) {
         try {
            var3 = this.inputRecord.read(var1.netData);
         } catch (IOException var7) {
            this.fatal((byte)10, (Throwable)var7);
         }

         try {
            var4 = this.inputRecord.decrypt(this.readCipher, var3);
         } catch (BadPaddingException var9) {
            var3.rewind();
            this.inputRecord.checkMAC(this.readMAC, var3);
            int var6 = this.inputRecord.contentType() == 22 ? 40 : 20;
            this.fatal((byte)var6, "Invalid padding", var9);
         }

         if (!this.inputRecord.checkMAC(this.readMAC, var4)) {
            if (this.inputRecord.contentType() == 22) {
               this.fatal((byte)40, (String)"bad handshake record MAC");
            } else {
               this.fatal((byte)20, (String)"bad record MAC");
            }
         }

         synchronized(this) {
            switch(this.inputRecord.contentType()) {
            case 20:
               if (this.connectionState != 1 && this.connectionState != 3 || this.inputRecord.available() != 1 || this.inputRecord.read() != 1) {
                  this.fatal((byte)10, (String)("illegal change cipher spec msg, state = " + this.connectionState));
               }

               this.changeReadCiphers();
               this.expectingFinished = true;
               break;
            case 21:
               this.recvAlert();
               break;
            case 22:
               this.initHandshaker();
               if (!this.handshaker.activated()) {
                  if (this.connectionState == 3) {
                     this.handshaker.activate(this.protocolVersion);
                  } else {
                     this.handshaker.activate((ProtocolVersion)null);
                  }
               }

               this.handshaker.process_record(this.inputRecord, this.expectingFinished);
               this.expectingFinished = false;
               if (this.handshaker.invalidated) {
                  this.handshaker = null;
                  if (this.connectionState == 3) {
                     this.connectionState = 2;
                  }
               } else if (this.handshaker.isDone()) {
                  this.secureRenegotiation = this.handshaker.isSecureRenegotiation();
                  this.clientVerifyData = this.handshaker.getClientVerifyData();
                  this.serverVerifyData = this.handshaker.getServerVerifyData();
                  this.sess = this.handshaker.getSession();
                  this.handshakeSession = null;
                  if (!this.writer.hasOutboundData()) {
                     var2 = HandshakeStatus.FINISHED;
                  }

                  this.handshaker = null;
                  this.connectionState = 2;
               } else if (this.handshaker.taskOutstanding()) {
                  var2 = HandshakeStatus.NEED_TASK;
               }
               break;
            case 23:
               if (this.connectionState != 2 && this.connectionState != 3 && this.connectionState != 6) {
                  throw new SSLProtocolException("Data received in non-data state: " + this.connectionState);
               }

               if (this.expectingFinished) {
                  throw new SSLProtocolException("Expecting finished message, received data");
               }

               if (!this.inboundDone) {
                  var1.scatter(var4.slice());
               }
               break;
            default:
               if (debug != null && Debug.isOn("ssl")) {
                  System.out.println(threadName() + ", Received record type: " + this.inputRecord.contentType());
               }
            }

            if (this.connectionState < 4 && !this.isInboundDone() && var2 == HandshakeStatus.NOT_HANDSHAKING && this.checkSequenceNumber(this.readMAC, this.inputRecord.contentType())) {
               var2 = this.getHSStatus((HandshakeStatus)null);
            }
         }
      }

      return var2;
   }

   public SSLEngineResult wrap(ByteBuffer[] var1, int var2, int var3, ByteBuffer var4) throws SSLException {
      EngineArgs var5 = new EngineArgs(var1, var2, var3, var4);
      if (var4.remaining() < 16921) {
         return new SSLEngineResult(Status.BUFFER_OVERFLOW, this.getHSStatus((HandshakeStatus)null), 0, 0);
      } else {
         try {
            Object var6 = this.wrapLock;
            synchronized(this.wrapLock) {
               SSLEngineResult var8 = this.writeAppRecord(var5);
               return var8;
            }
         } catch (Exception var13) {
            var5.resetPos();
            this.fatal((byte)80, "problem unwrapping net record", var13);
         } finally {
            var5.resetLim();
         }

         return null;
      }
   }

   private SSLEngineResult writeAppRecord(EngineArgs var1) throws IOException {
      Status var2 = null;
      HandshakeStatus var3 = null;
      this.checkTaskThrown();
      if (this.writer.isOutboundDone()) {
         return new SSLEngineResult(Status.CLOSED, this.getHSStatus((HandshakeStatus)null), 0, 0);
      } else {
         synchronized(this) {
            if (this.connectionState == 1 || this.connectionState == 0) {
               this.kickstartHandshake();
               var3 = this.getHSStatus((HandshakeStatus)null);
               if (var3 == HandshakeStatus.NEED_UNWRAP) {
                  return new SSLEngineResult(Status.OK, var3, 0, 0);
               }
            }
         }

         if (var3 == null) {
            var3 = this.getHSStatus((HandshakeStatus)null);
         }

         if (var3 == HandshakeStatus.NEED_TASK) {
            return new SSLEngineResult(Status.OK, var3, 0, 0);
         } else {
            try {
               Object var4 = this.writeLock;
               synchronized(this.writeLock) {
                  var3 = this.writeRecord(this.outputRecord, var1);
               }
            } catch (SSLException var7) {
               throw var7;
            } catch (IOException var8) {
               SSLException var5 = new SSLException("Write problems");
               var5.initCause(var8);
               throw var5;
            }

            var2 = this.isOutboundDone() ? Status.CLOSED : Status.OK;
            var3 = this.getHSStatus(var3);
            return new SSLEngineResult(var2, var3, var1.deltaApp(), var1.deltaNet());
         }
      }
   }

   private HandshakeStatus writeRecord(EngineOutputRecord var1, EngineArgs var2) throws IOException {
      HandshakeStatus var3 = this.writer.writeRecord(var1, var2, this.writeMAC, this.writeCipher);
      if (this.connectionState < 4 && !this.isOutboundDone() && var3 == HandshakeStatus.NOT_HANDSHAKING && this.checkSequenceNumber(this.writeMAC, var1.contentType())) {
         var3 = this.getHSStatus((HandshakeStatus)null);
      }

      return var3;
   }

   void writeRecord(EngineOutputRecord var1) throws IOException {
      this.writer.writeRecord(var1, this.writeMAC, this.writeCipher);
      if (this.connectionState < 4 && !this.isOutboundDone()) {
         this.checkSequenceNumber(this.writeMAC, var1.contentType());
      }

   }

   private boolean checkSequenceNumber(MAC var1, byte var2) throws IOException {
      if (this.connectionState < 4 && var1 != MAC.NULL) {
         if (var1.seqNumOverflow()) {
            if (debug != null && Debug.isOn("ssl")) {
               System.out.println(threadName() + ", sequence number extremely close to overflow " + "(2^64-1 packets). Closing connection.");
            }

            this.fatal((byte)40, (String)"sequence number overflow");
            return true;
         } else if (var2 != 22 && var1.seqNumIsHuge()) {
            if (debug != null && Debug.isOn("ssl")) {
               System.out.println(threadName() + ", request renegotiation " + "to avoid sequence number overflow");
            }

            this.beginHandshake();
            return true;
         } else {
            return false;
         }
      } else {
         return false;
      }
   }

   private void closeOutboundInternal() {
      if (debug != null && Debug.isOn("ssl")) {
         System.out.println(threadName() + ", closeOutboundInternal()");
      }

      if (!this.writer.isOutboundDone()) {
         switch(this.connectionState) {
         case 0:
            this.writer.closeOutbound();
            this.inboundDone = true;
            break;
         case 1:
         case 2:
         case 3:
         case 5:
         default:
            this.warning((byte)0);
            this.writer.closeOutbound();
         case 4:
         case 6:
         }

         this.writeCipher.dispose();
         this.connectionState = 6;
      }
   }

   public synchronized void closeOutbound() {
      if (debug != null && Debug.isOn("ssl")) {
         System.out.println(threadName() + ", called closeOutbound()");
      }

      this.closeOutboundInternal();
   }

   public boolean isOutboundDone() {
      return this.writer.isOutboundDone();
   }

   private void closeInboundInternal() {
      if (debug != null && Debug.isOn("ssl")) {
         System.out.println(threadName() + ", closeInboundInternal()");
      }

      if (!this.inboundDone) {
         this.closeOutboundInternal();
         this.inboundDone = true;
         this.readCipher.dispose();
         this.connectionState = 6;
      }
   }

   public synchronized void closeInbound() throws SSLException {
      if (debug != null && Debug.isOn("ssl")) {
         System.out.println(threadName() + ", called closeInbound()");
      }

      if (this.connectionState != 0 && !this.recvCN) {
         this.recvCN = true;
         this.fatal((byte)80, (String)"Inbound closed before receiving peer's close_notify: possible truncation attack?");
      } else {
         this.closeInboundInternal();
      }

   }

   public synchronized boolean isInboundDone() {
      return this.inboundDone;
   }

   public synchronized SSLSession getSession() {
      return this.sess;
   }

   public synchronized SSLSession getHandshakeSession() {
      return this.handshakeSession;
   }

   synchronized void setHandshakeSession(SSLSessionImpl var1) {
      this.handshakeSession = var1;
   }

   public synchronized Runnable getDelegatedTask() {
      return this.handshaker != null ? this.handshaker.getTask() : null;
   }

   void warning(byte var1) {
      this.sendAlert((byte)1, var1);
   }

   synchronized void fatal(byte var1, String var2) throws SSLException {
      this.fatal(var1, var2, (Throwable)null);
   }

   synchronized void fatal(byte var1, Throwable var2) throws SSLException {
      this.fatal(var1, (String)null, var2);
   }

   synchronized void fatal(byte var1, String var2, Throwable var3) throws SSLException {
      if (var2 == null) {
         var2 = "General SSLEngine problem";
      }

      if (var3 == null) {
         var3 = Alerts.getSSLException(var1, (Throwable)var3, var2);
      }

      if (this.closeReason != null) {
         if (debug != null && Debug.isOn("ssl")) {
            System.out.println(threadName() + ", fatal: engine already closed.  Rethrowing " + ((Throwable)var3).toString());
         }

         if (var3 instanceof RuntimeException) {
            throw (RuntimeException)var3;
         }

         if (var3 instanceof SSLException) {
            throw (SSLException)var3;
         }

         if (var3 instanceof Exception) {
            SSLException var5 = new SSLException("fatal SSLEngine condition");
            var5.initCause((Throwable)var3);
            throw var5;
         }
      }

      if (debug != null && Debug.isOn("ssl")) {
         System.out.println(threadName() + ", fatal error: " + var1 + ": " + var2 + "\n" + ((Throwable)var3).toString());
      }

      int var4 = this.connectionState;
      this.connectionState = 4;
      this.inboundDone = true;
      this.sess.invalidate();
      if (this.handshakeSession != null) {
         this.handshakeSession.invalidate();
      }

      if (var4 != 0) {
         this.sendAlert((byte)2, var1);
      }

      if (var3 instanceof SSLException) {
         this.closeReason = (SSLException)var3;
      } else {
         this.closeReason = Alerts.getSSLException(var1, (Throwable)var3, var2);
      }

      this.writer.closeOutbound();
      this.connectionState = 6;
      this.readCipher.dispose();
      this.writeCipher.dispose();
      if (var3 instanceof RuntimeException) {
         throw (RuntimeException)var3;
      } else {
         throw this.closeReason;
      }
   }

   private void recvAlert() throws IOException {
      byte var1 = (byte)this.inputRecord.read();
      byte var2 = (byte)this.inputRecord.read();
      if (var2 == -1) {
         this.fatal((byte)47, (String)"Short alert message");
      }

      if (debug != null && (Debug.isOn("record") || Debug.isOn("handshake"))) {
         PrintStream var3 = System.out;
         synchronized(System.out) {
            System.out.print(threadName());
            System.out.print(", RECV " + this.protocolVersion + " ALERT:  ");
            if (var1 == 2) {
               System.out.print("fatal, ");
            } else if (var1 == 1) {
               System.out.print("warning, ");
            } else {
               System.out.print("<level " + (255 & var1) + ">, ");
            }

            System.out.println(Alerts.alertDescription(var2));
         }
      }

      if (var1 == 1) {
         if (var2 == 0) {
            if (this.connectionState == 1) {
               this.fatal((byte)10, (String)"Received close_notify during handshake");
            } else {
               this.recvCN = true;
               this.closeInboundInternal();
            }
         } else if (this.handshaker != null) {
            this.handshaker.handshakeAlert(var2);
         }
      } else {
         String var5 = "Received fatal alert: " + Alerts.alertDescription(var2);
         if (this.closeReason == null) {
            this.closeReason = Alerts.getSSLException(var2, var5);
         }

         this.fatal((byte)10, (String)var5);
      }

   }

   private void sendAlert(byte var1, byte var2) {
      if (this.connectionState < 6) {
         if (this.connectionState != 1 || this.handshaker != null && this.handshaker.started()) {
            EngineOutputRecord var3 = new EngineOutputRecord((byte)21, this);
            var3.setVersion(this.protocolVersion);
            boolean var4 = debug != null && Debug.isOn("ssl");
            if (var4) {
               PrintStream var5 = System.out;
               synchronized(System.out) {
                  System.out.print(threadName());
                  System.out.print(", SEND " + this.protocolVersion + " ALERT:  ");
                  if (var1 == 2) {
                     System.out.print("fatal, ");
                  } else if (var1 == 1) {
                     System.out.print("warning, ");
                  } else {
                     System.out.print("<level = " + (255 & var1) + ">, ");
                  }

                  System.out.println("description = " + Alerts.alertDescription(var2));
               }
            }

            var3.write(var1);
            var3.write(var2);

            try {
               this.writeRecord(var3);
            } catch (IOException var7) {
               if (var4) {
                  System.out.println(threadName() + ", Exception sending alert: " + var7);
               }
            }

         }
      }
   }

   public synchronized void setEnableSessionCreation(boolean var1) {
      this.enableSessionCreation = var1;
      if (this.handshaker != null && !this.handshaker.activated()) {
         this.handshaker.setEnableSessionCreation(this.enableSessionCreation);
      }

   }

   public synchronized boolean getEnableSessionCreation() {
      return this.enableSessionCreation;
   }

   public synchronized void setNeedClientAuth(boolean var1) {
      this.doClientAuth = (byte)(var1 ? 2 : 0);
      if (this.handshaker != null && this.handshaker instanceof ServerHandshaker && !this.handshaker.activated()) {
         ((ServerHandshaker)this.handshaker).setClientAuth(this.doClientAuth);
      }

   }

   public synchronized boolean getNeedClientAuth() {
      return this.doClientAuth == 2;
   }

   public synchronized void setWantClientAuth(boolean var1) {
      this.doClientAuth = (byte)(var1 ? 1 : 0);
      if (this.handshaker != null && this.handshaker instanceof ServerHandshaker && !this.handshaker.activated()) {
         ((ServerHandshaker)this.handshaker).setClientAuth(this.doClientAuth);
      }

   }

   public synchronized boolean getWantClientAuth() {
      return this.doClientAuth == 1;
   }

   public synchronized void setUseClientMode(boolean var1) {
      switch(this.connectionState) {
      case 0:
         if (this.roleIsServer != !var1 && this.sslContext.isDefaultProtocolList(this.enabledProtocols)) {
            this.enabledProtocols = this.sslContext.getDefaultProtocolList(!var1);
         }

         this.roleIsServer = !var1;
         this.serverModeSet = true;
         break;
      case 1:
         assert this.handshaker != null;

         if (!this.handshaker.activated()) {
            if (this.roleIsServer != !var1 && this.sslContext.isDefaultProtocolList(this.enabledProtocols)) {
               this.enabledProtocols = this.sslContext.getDefaultProtocolList(!var1);
            }

            this.roleIsServer = !var1;
            this.connectionState = 0;
            this.initHandshaker();
            break;
         }
      default:
         if (debug != null && Debug.isOn("ssl")) {
            System.out.println(threadName() + ", setUseClientMode() invoked in state = " + this.connectionState);
         }

         throw new IllegalArgumentException("Cannot change mode after SSL traffic has started");
      }

   }

   public synchronized boolean getUseClientMode() {
      return !this.roleIsServer;
   }

   public String[] getSupportedCipherSuites() {
      return this.sslContext.getSuportedCipherSuiteList().toStringArray();
   }

   public synchronized void setEnabledCipherSuites(String[] var1) {
      if (GMConf.debug) {
         System.out.println("setEnabledCipherSuites2");
      }

      if (GMConf.debug) {
         for(int var2 = 0; var2 < var1.length; ++var2) {
            System.out.println("setEnabledCipherSuites2 suites[" + var2 + "]=" + var1[var2]);
         }
      }

      this.enabledCipherSuites = new CipherSuiteList(var1);
      if (this.handshaker != null && !this.handshaker.activated()) {
         this.handshaker.setEnabledCipherSuites(this.enabledCipherSuites);
      }

   }

   public synchronized String[] getEnabledCipherSuites() {
      return this.enabledCipherSuites.toStringArray();
   }

   public String[] getSupportedProtocols() {
      return this.sslContext.getSuportedProtocolList().toStringArray();
   }

   public synchronized void setEnabledProtocols(String[] var1) {
      if (GMConf.debug) {
         for(int var2 = 0; var2 < var1.length; ++var2) {
            System.out.println("setEnabledProtocols protocols[" + var2 + "]=" + var1[var2]);
         }
      }

      this.enabledProtocols = new ProtocolList(var1);
      if (this.handshaker != null && !this.handshaker.activated()) {
         this.handshaker.setEnabledProtocols(this.enabledProtocols);
      }

   }

   public synchronized String[] getEnabledProtocols() {
      return this.enabledProtocols.toStringArray();
   }

   public synchronized SSLParameters getSSLParameters() {
      SSLParameters var1 = super.getSSLParameters();
      var1.setEndpointIdentificationAlgorithm(this.identificationProtocol);
      var1.setAlgorithmConstraints(this.algorithmConstraints);
      return var1;
   }

   public synchronized void setSSLParameters(SSLParameters var1) {
      super.setSSLParameters(var1);
      this.identificationProtocol = var1.getEndpointIdentificationAlgorithm();
      this.algorithmConstraints = var1.getAlgorithmConstraints();
      if (this.handshaker != null && !this.handshaker.started()) {
         this.handshaker.setIdentificationProtocol(this.identificationProtocol);
         this.handshaker.setAlgorithmConstraints(this.algorithmConstraints);
      }

   }

   private static String threadName() {
      return Thread.currentThread().getName();
   }

   public String toString() {
      StringBuilder var1 = new StringBuilder(80);
      var1.append(Integer.toHexString(this.hashCode()));
      var1.append("[");
      var1.append("SSLEngine[hostname=");
      String var2 = this.getPeerHost();
      var1.append(var2 == null ? "null" : var2);
      var1.append(" port=");
      var1.append(Integer.toString(this.getPeerPort()));
      var1.append("] ");
      var1.append(this.getSession().getCipherSuite());
      var1.append("]");
      return var1.toString();
   }
}
