package cn.gmssl.sun.security.ssl;

import cn.gmssl.jsse.provider.GMConf;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.AlgorithmConstraints;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import javax.crypto.BadPaddingException;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.SSLSession;

public final class SSLSocketImpl extends BaseSSLSocketImpl {
   private static final int cs_START = 0;
   private static final int cs_HANDSHAKE = 1;
   private static final int cs_DATA = 2;
   private static final int cs_RENEGOTIATE = 3;
   private static final int cs_ERROR = 4;
   private static final int cs_SENT_CLOSE = 5;
   private static final int cs_CLOSED = 6;
   private static final int cs_APP_CLOSED = 7;
   private int connectionState;
   private boolean expectingFinished;
   private SSLException closeReason;
   private byte doClientAuth;
   private boolean roleIsServer;
   private boolean enableSessionCreation = true;
   private String host;
   private boolean autoClose = true;
   private AccessControlContext acc;
   private String rawHostname;
   private CipherSuiteList enabledCipherSuites;
   private String identificationProtocol = null;
   private AlgorithmConstraints algorithmConstraints = null;
   private final Object handshakeLock = new Object();
   final ReentrantLock writeLock = new ReentrantLock();
   private final Object readLock = new Object();
   private InputRecord inrec;
   private MAC readMAC;
   private MAC writeMAC;
   private CipherBox readCipher;
   private CipherBox writeCipher;
   private boolean secureRenegotiation;
   private byte[] clientVerifyData;
   private byte[] serverVerifyData;
   private SSLContextImpl sslContext;
   private Handshaker handshaker;
   private SSLSessionImpl sess;
   private volatile SSLSessionImpl handshakeSession;
   private int count = 0;
   private HashMap<HandshakeCompletedListener, AccessControlContext> handshakeListeners;
   private InputStream sockInput;
   private OutputStream sockOutput;
   private AppInputStream input;
   private AppOutputStream output;
   private ProtocolList enabledProtocols;
   private ProtocolVersion protocolVersion;
   private static final Debug debug = Debug.getInstance("ssl");

   SSLSocketImpl(SSLContextImpl var1, String var2, int var3) throws IOException, UnknownHostException {
      this.protocolVersion = ProtocolVersion.DEFAULT;
      this.host = var2;
      this.rawHostname = var2;
      this.init(var1, false);
      InetSocketAddress var4 = var2 != null ? new InetSocketAddress(var2, var3) : new InetSocketAddress(InetAddress.getByName((String)null), var3);
      this.connect(var4, 0);
   }

   SSLSocketImpl(SSLContextImpl var1, InetAddress var2, int var3) throws IOException {
      this.protocolVersion = ProtocolVersion.DEFAULT;
      this.init(var1, false);
      InetSocketAddress var4 = new InetSocketAddress(var2, var3);
      this.connect(var4, 0);
   }

   SSLSocketImpl(SSLContextImpl var1, String var2, int var3, InetAddress var4, int var5) throws IOException, UnknownHostException {
      this.protocolVersion = ProtocolVersion.DEFAULT;
      this.host = var2;
      this.rawHostname = var2;
      this.init(var1, false);
      this.bind(new InetSocketAddress(var4, var5));
      InetSocketAddress var6 = var2 != null ? new InetSocketAddress(var2, var3) : new InetSocketAddress(InetAddress.getByName((String)null), var3);
      this.connect(var6, 0);
   }

   SSLSocketImpl(SSLContextImpl var1, InetAddress var2, int var3, InetAddress var4, int var5) throws IOException {
      this.protocolVersion = ProtocolVersion.DEFAULT;
      this.init(var1, false);
      this.bind(new InetSocketAddress(var4, var5));
      InetSocketAddress var6 = new InetSocketAddress(var2, var3);
      this.connect(var6, 0);
   }

   SSLSocketImpl(SSLContextImpl var1, boolean var2, CipherSuiteList var3, byte var4, boolean var5, ProtocolList var6, String var7, AlgorithmConstraints var8) throws IOException {
      this.protocolVersion = ProtocolVersion.DEFAULT;
      this.doClientAuth = var4;
      this.enableSessionCreation = var5;
      this.identificationProtocol = var7;
      this.algorithmConstraints = var8;
      this.init(var1, var2);
      if (GMConf.debug) {
         System.out.println("SSLSocketImpl construct enabledCipherSuites=" + this.enabledCipherSuites);
      }

      this.enabledCipherSuites = var3;
      this.enabledProtocols = var6;
   }

   SSLSocketImpl(SSLContextImpl var1) {
      this.protocolVersion = ProtocolVersion.DEFAULT;
      this.init(var1, false);
   }

   SSLSocketImpl(SSLContextImpl var1, Socket var2, String var3, int var4, boolean var5) throws IOException {
      super(var2);
      this.protocolVersion = ProtocolVersion.DEFAULT;
      if (!var2.isConnected()) {
         throw new SocketException("Underlying socket is not connected");
      } else {
         this.host = var3;
         this.rawHostname = var3;
         this.init(var1, false);
         this.autoClose = var5;
         this.doneConnect();
      }
   }

   private void init(SSLContextImpl var1, boolean var2) {
      this.sslContext = var1;
      this.sess = SSLSessionImpl.nullSession;
      this.handshakeSession = null;
      this.roleIsServer = var2;
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
      if (GMConf.debug) {
         System.out.println("SSLSocketImpl init enabledCipherSuites=" + this.enabledCipherSuites);
      }

      this.inrec = null;
      this.input = new AppInputStream(this);
      this.output = new AppOutputStream(this);
   }

   public void connect(SocketAddress var1, int var2) throws IOException {
      if (this.self != this) {
         throw new SocketException("Already connected");
      } else if (!(var1 instanceof InetSocketAddress)) {
         throw new SocketException("Cannot handle non-Inet socket addresses.");
      } else {
         super.connect(var1, var2);
         this.doneConnect();
      }
   }

   void doneConnect() throws IOException {
      if (this.self == this) {
         this.sockInput = super.getInputStream();
         this.sockOutput = super.getOutputStream();
      } else {
         this.sockInput = this.self.getInputStream();
         this.sockOutput = this.self.getOutputStream();
      }

      this.initHandshaker();
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

   void writeRecord(OutputRecord var1) throws IOException {
      while(true) {
         if (var1.contentType() == 23) {
            switch(this.getConnectionState()) {
            case 1:
               this.performInitialHandshake();
               continue;
            case 2:
            case 3:
               break;
            case 4:
               this.fatal((byte)0, (String)"error while writing to socket");
               continue;
            case 5:
            case 6:
            case 7:
               if (this.closeReason != null) {
                  throw this.closeReason;
               }

               throw new SocketException("Socket closed");
            default:
               throw new SSLProtocolException("State error, send app data");
            }
         }

         if (!var1.isEmpty()) {
            if (var1.isAlert((byte)0) && this.getSoLinger() >= 0) {
               boolean var2 = Thread.interrupted();

               try {
                  if (this.writeLock.tryLock((long)this.getSoLinger(), TimeUnit.SECONDS)) {
                     try {
                        this.writeRecordInternal(var1);
                     } finally {
                        this.writeLock.unlock();
                     }
                  } else {
                     SSLException var3 = new SSLException("SO_LINGER timeout, close_notify message cannot be sent.");
                     if (this.self != this && !this.autoClose) {
                        this.fatal((byte)-1, (Throwable)var3);
                     } else if (debug != null && Debug.isOn("ssl")) {
                        System.out.println(threadName() + ", received Exception: " + var3);
                     }

                     this.sess.invalidate();
                  }
               } catch (InterruptedException var12) {
                  var2 = true;
               }

               if (var2) {
                  Thread.currentThread().interrupt();
               }
            } else {
               this.writeLock.lock();

               try {
                  this.writeRecordInternal(var1);
               } finally {
                  this.writeLock.unlock();
               }
            }
         }

         return;
      }
   }

   private void writeRecordInternal(OutputRecord var1) throws IOException {
      var1.addMAC(this.writeMAC);
      var1.encrypt(this.writeCipher);
      var1.write(this.sockOutput);
      if (this.connectionState < 4) {
         this.checkSequenceNumber(this.writeMAC, var1.contentType());
      }

   }

   void readDataRecord(InputRecord var1) throws IOException {
      if (this.getConnectionState() == 1) {
         this.performInitialHandshake();
      }

      this.readRecord(var1, true);
   }

   private void readRecord(InputRecord var1, boolean var2) throws IOException {
      Object var4 = this.readLock;
      synchronized(this.readLock) {
         while(true) {
            int var3;
            if ((var3 = this.getConnectionState()) != 6 && var3 != 4 && var3 != 7) {
               try {
                  var1.setAppDataValid(false);
                  var1.read(this.sockInput, this.sockOutput);
               } catch (SSLProtocolException var10) {
                  SSLProtocolException var5 = var10;

                  try {
                     this.fatal((byte)10, (Throwable)var5);
                  } catch (IOException var9) {
                     ;
                  }

                  throw var10;
               } catch (EOFException var11) {
                  boolean var6 = this.getConnectionState() <= 1;
                  boolean var7 = requireCloseNotify || var6;
                  if (debug != null && Debug.isOn("ssl")) {
                     System.out.println(threadName() + ", received EOFException: " + (var7 ? "error" : "ignored"));
                  }

                  if (var7) {
                     IOException var8;
                     if (var6) {
                        var8 = new SSLHandshakeException("Remote host closed connection during handshake");
                     } else {
                        var8 = new SSLProtocolException("Remote host closed connection incorrectly");
                     }

                     ((SSLException)var8).initCause(var11);
                     throw var8;
                  }

                  this.closeInternal(false);
                  continue;
               }

               try {
                  var1.decrypt(this.readCipher);
               } catch (BadPaddingException var13) {
                  System.err.println("dump--------------------------------------");
                  System.err.println("thread:" + Thread.currentThread().getId() + "-" + ++this.count);
                  System.err.println(this.handshaker.sb.toString());
                  var1.checkMAC(this.readMAC);
                  int var15 = var1.contentType() == 22 ? 40 : 20;
                  this.fatal((byte)var15, "Invalid padding", var13);
               }

               if (!var1.checkMAC(this.readMAC)) {
                  if (var1.contentType() == 22) {
                     this.fatal((byte)40, (String)"bad handshake record MAC");
                  } else {
                     this.fatal((byte)20, (String)"bad record MAC");
                  }
               }

               synchronized(this) {
                  switch(var1.contentType()) {
                  case 20:
                     if (this.connectionState != 1 && this.connectionState != 3 || var1.available() != 1 || var1.read() != 1) {
                        this.fatal((byte)10, (String)("illegal change cipher spec msg, state = " + this.connectionState));
                     }

                     this.changeReadCiphers();
                     this.expectingFinished = true;
                     continue;
                  case 21:
                     this.recvAlert(var1);
                     continue;
                  case 22:
                     this.initHandshaker();
                     if (!this.handshaker.activated()) {
                        if (this.connectionState == 3) {
                           this.handshaker.activate(this.protocolVersion);
                        } else {
                           this.handshaker.activate((ProtocolVersion)null);
                        }
                     }

                     this.handshaker.process_record(var1, this.expectingFinished);
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
                        this.handshaker = null;
                        this.connectionState = 2;
                        if (this.handshakeListeners != null) {
                           HandshakeCompletedEvent var16 = new HandshakeCompletedEvent(this, this.sess);
                           SSLSocketImpl.NotifyHandshakeThread var17 = new SSLSocketImpl.NotifyHandshakeThread(this.handshakeListeners.entrySet(), var16);
                           var17.start();
                        }
                     }

                     if (var2 || this.connectionState != 2) {
                        continue;
                     }
                     break;
                  case 23:
                     if (this.connectionState != 2 && this.connectionState != 3 && this.connectionState != 5) {
                        throw new SSLProtocolException("Data received in non-data state: " + this.connectionState);
                     }

                     if (this.expectingFinished) {
                        throw new SSLProtocolException("Expecting finished message, received data");
                     }

                     if (!var2) {
                        throw new SSLException("Discarding app data");
                     }

                     var1.setAppDataValid(true);
                     break;
                  default:
                     if (debug != null && Debug.isOn("ssl")) {
                        System.out.println(threadName() + ", Received record type: " + var1.contentType());
                     }
                     continue;
                  }

                  if (this.connectionState < 4) {
                     this.checkSequenceNumber(this.readMAC, var1.contentType());
                  }
               }

               return;
            }

            var1.close();
            return;
         }
      }
   }

   private void checkSequenceNumber(MAC var1, byte var2) throws IOException {
      if (this.connectionState < 4 && var1 != MAC.NULL) {
         if (var1.seqNumOverflow()) {
            if (debug != null && Debug.isOn("ssl")) {
               System.out.println(threadName() + ", sequence number extremely close to overflow " + "(2^64-1 packets). Closing connection.");
            }

            this.fatal((byte)40, (String)"sequence number overflow");
         }

         if (var2 != 22 && var1.seqNumIsHuge()) {
            if (debug != null && Debug.isOn("ssl")) {
               System.out.println(threadName() + ", request renegotiation " + "to avoid sequence number overflow");
            }

            this.startHandshake();
         }

      }
   }

   AppInputStream getAppInputStream() {
      return this.input;
   }

   AppOutputStream getAppOutputStream() {
      return this.output;
   }

   private void initHandshaker() {
      if (GMConf.debug) {
         System.out.println("initHandshaker1");
      }

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
            System.out.println("SSLSocketImpl setEnabledCipherSuites=" + this.enabledCipherSuites);
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

   private void performInitialHandshake() throws IOException {
      Object var1 = this.handshakeLock;
      synchronized(this.handshakeLock) {
         if (this.getConnectionState() == 1) {
            this.kickstartHandshake();
            if (this.inrec == null) {
               this.inrec = new InputRecord();
               this.inrec.setHandshakeHash(this.input.r.getHandshakeHash());
               this.inrec.setHelloVersion(this.input.r.getHelloVersion());
               this.inrec.enableFormatChecks();
            }

            this.readRecord(this.inrec, false);
            this.inrec = null;
         }

      }
   }

   public void startHandshake() throws IOException {
      this.startHandshake(true);
   }

   private void startHandshake(boolean var1) throws IOException {
      this.checkWrite();

      try {
         if (this.getConnectionState() == 1) {
            this.performInitialHandshake();
         } else {
            this.kickstartHandshake();
         }
      } catch (Exception var3) {
         this.handleException(var3, var1);
      }

   }

   private synchronized void kickstartHandshake() throws IOException {
      switch(this.connectionState) {
      case 0:
         throw new SocketException("handshaking attempted on unconnected socket");
      case 2:
         if (!this.secureRenegotiation && !Handshaker.allowUnsafeRenegotiation) {
            throw new SSLHandshakeException("Insecure renegotiation is not allowed");
         } else {
            if (!this.secureRenegotiation && debug != null && Debug.isOn("handshake")) {
               System.out.println("Warning: Using insecure renegotiation");
            }

            this.initHandshaker();
         }
      case 1:
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

         return;
      case 3:
         return;
      default:
         throw new SocketException("connection is closed");
      }
   }

   public boolean isClosed() {
      return this.getConnectionState() == 7;
   }

   boolean checkEOF() throws IOException {
      switch(this.getConnectionState()) {
      case 0:
         throw new SocketException("Socket is not connected");
      case 1:
      case 2:
      case 3:
      case 5:
         return false;
      case 4:
      case 6:
      default:
         if (this.closeReason == null) {
            return true;
         }

         SSLException var1 = new SSLException("Connection has been shutdown: " + this.closeReason);
         var1.initCause(this.closeReason);
         throw var1;
      case 7:
         throw new SocketException("Socket is closed");
      }
   }

   void checkWrite() throws IOException {
      if (this.checkEOF() || this.getConnectionState() == 5) {
         throw new SocketException("Connection closed by remote host");
      }
   }

   protected void closeSocket() throws IOException {
      if (debug != null && Debug.isOn("ssl")) {
         System.out.println(threadName() + ", called closeSocket()");
      }

      if (this.self == this) {
         super.close();
      } else {
         this.self.close();
      }

   }

   private void closeSocket(boolean var1) throws IOException {
      if (debug != null && Debug.isOn("ssl")) {
         System.out.println(threadName() + ", called closeSocket(selfInitiated)");
      }

      if (this.self == this) {
         super.close();
      } else if (this.autoClose) {
         this.self.close();
      } else if (var1) {
         this.waitForClose(false);
      }

   }

   public void close() throws IOException {
      if (debug != null && Debug.isOn("ssl")) {
         System.out.println(threadName() + ", called close()");
      }

      this.closeInternal(true);
      this.setConnectionState(7);
   }

   private void closeInternal(boolean var1) throws IOException {
      if (debug != null && Debug.isOn("ssl")) {
         System.out.println(threadName() + ", called closeInternal(" + var1 + ")");
      }

      int var2 = this.getConnectionState();
      boolean var3 = false;
      Throwable var4 = null;

      try {
         switch(var2) {
         case 0:
         case 6:
         case 7:
            return;
         case 1:
         case 2:
         case 3:
         case 5:
         default:
            synchronized(this) {
               if ((var2 = this.getConnectionState()) == 6 || var2 == 4 || var2 == 7) {
                  return;
               }

               if (var2 != 5) {
                  try {
                     this.warning((byte)0);
                     this.connectionState = 5;
                  } catch (Throwable var21) {
                     this.connectionState = 4;
                     var4 = var21;
                     var3 = true;
                     this.closeSocket(var1);
                  }
               }
            }

            if (var2 == 5) {
               if (debug != null && Debug.isOn("ssl")) {
                  System.out.println(threadName() + ", close invoked again; state = " + this.getConnectionState());
               }

               if (var1) {
                  synchronized(this) {
                     while(this.connectionState < 6) {
                        try {
                           this.wait();
                        } catch (InterruptedException var20) {
                           ;
                        }
                     }
                  }

                  if (debug != null && Debug.isOn("ssl")) {
                     System.out.println(threadName() + ", after primary close; state = " + this.getConnectionState());
                  }

                  return;
               }

               return;
            }

            if (!var3) {
               var3 = true;
               this.closeSocket(var1);
            }

            return;
         case 4:
            this.closeSocket();
         }
      } finally {
         synchronized(this) {
            this.connectionState = this.connectionState == 7 ? 7 : 6;
            this.notifyAll();
         }

         if (var3) {
            this.disposeCiphers();
         }

         if (var4 != null) {
            if (var4 instanceof Error) {
               throw (Error)var4;
            }

            if (var4 instanceof RuntimeException) {
               throw (RuntimeException)var4;
            }
         }

      }
   }

   void waitForClose(boolean var1) throws IOException {
      if (debug != null && Debug.isOn("ssl")) {
         System.out.println(threadName() + ", waiting for close_notify or alert: state " + this.getConnectionState());
      }

      try {
         int var2;
         while((var2 = this.getConnectionState()) != 6 && var2 != 4 && var2 != 7) {
            if (this.inrec == null) {
               this.inrec = new InputRecord();
            }

            try {
               this.readRecord(this.inrec, true);
            } catch (SocketTimeoutException var4) {
               ;
            }
         }

         this.inrec = null;
      } catch (IOException var5) {
         if (debug != null && Debug.isOn("ssl")) {
            System.out.println(threadName() + ", Exception while waiting for close " + var5);
         }

         if (var1) {
            throw var5;
         }
      }

   }

   private void disposeCiphers() {
      Object var1 = this.readLock;
      synchronized(this.readLock) {
         this.readCipher.dispose();
      }

      this.writeLock.lock();

      try {
         this.writeCipher.dispose();
      } finally {
         this.writeLock.unlock();
      }

   }

   void handleException(Exception var1) throws IOException {
      this.handleException(var1, true);
   }

   private synchronized void handleException(Exception var1, boolean var2) throws IOException {
      if (debug != null && Debug.isOn("ssl")) {
         var1.printStackTrace();
         System.out.println(threadName() + ", handling exception: " + var1.toString());
      }

      if (var1 instanceof InterruptedIOException && var2) {
         throw (IOException)var1;
      } else if (this.closeReason != null) {
         if (var1 instanceof IOException) {
            throw (IOException)var1;
         } else {
            throw Alerts.getSSLException((byte)80, var1, "Unexpected exception");
         }
      } else {
         boolean var3 = var1 instanceof SSLException;
         if (!var3 && var1 instanceof IOException) {
            try {
               this.fatal((byte)10, (Throwable)var1);
            } catch (IOException var5) {
               ;
            }

            throw (IOException)var1;
         } else {
            byte var4;
            if (var3) {
               if (var1 instanceof SSLHandshakeException) {
                  var4 = 40;
               } else {
                  var4 = 10;
               }
            } else {
               var4 = 80;
            }

            this.fatal(var4, (Throwable)var1);
         }
      }
   }

   void warning(byte var1) {
      this.sendAlert((byte)1, var1);
   }

   synchronized void fatal(byte var1, String var2) throws IOException {
      this.fatal(var1, var2, (Throwable)null);
   }

   synchronized void fatal(byte var1, Throwable var2) throws IOException {
      this.fatal(var1, (String)null, var2);
   }

   synchronized void fatal(byte var1, String var2, Throwable var3) throws IOException {
      if (this.input != null && this.input.r != null) {
         this.input.r.close();
      }

      this.sess.invalidate();
      if (this.handshakeSession != null) {
         this.handshakeSession.invalidate();
      }

      int var4 = this.connectionState;
      if (this.connectionState < 4) {
         this.connectionState = 4;
      }

      if (this.closeReason == null) {
         if (var4 == 1) {
            this.sockInput.skip((long)this.sockInput.available());
         }

         if (var1 != -1) {
            this.sendAlert((byte)2, var1);
         }

         if (var3 instanceof SSLException) {
            this.closeReason = (SSLException)var3;
         } else {
            this.closeReason = Alerts.getSSLException(var1, var3, var2);
         }
      }

      this.closeSocket();
      if (this.connectionState < 6) {
         this.connectionState = var4 == 7 ? 7 : 6;
         this.readCipher.dispose();
         this.writeCipher.dispose();
      }

      throw this.closeReason;
   }

   private void recvAlert(InputRecord var1) throws IOException {
      byte var2 = (byte)var1.read();
      byte var3 = (byte)var1.read();
      if (var3 == -1) {
         this.fatal((byte)47, (String)"Short alert message");
      }

      if (debug != null && (Debug.isOn("record") || Debug.isOn("handshake"))) {
         PrintStream var4 = System.out;
         synchronized(System.out) {
            System.out.print(threadName());
            System.out.print(", RECV " + this.protocolVersion + " ALERT:  ");
            if (var2 == 2) {
               System.out.print("fatal, ");
            } else if (var2 == 1) {
               System.out.print("warning, ");
            } else {
               System.out.print("<level " + (255 & var2) + ">, ");
            }

            System.out.println(Alerts.alertDescription(var3));
         }
      }

      if (var2 == 1) {
         if (var3 == 0) {
            if (this.connectionState == 1) {
               this.fatal((byte)10, (String)"Received close_notify during handshake");
            } else {
               this.closeInternal(false);
            }
         } else if (this.handshaker != null) {
            this.handshaker.handshakeAlert(var3);
         }
      } else {
         String var6 = "Received fatal alert: " + Alerts.alertDescription(var3);
         if (this.closeReason == null) {
            this.closeReason = Alerts.getSSLException(var3, var6);
         }

         this.fatal((byte)10, (String)var6);
      }

   }

   private void sendAlert(byte var1, byte var2) {
      if (this.connectionState < 5) {
         if (this.connectionState != 1 || this.handshaker != null && this.handshaker.started()) {
            OutputRecord var3 = new OutputRecord((byte)21);
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
      this.output.r.setVersion(var1);
   }

   synchronized String getHost() {
      if (this.host == null || this.host.length() == 0) {
         this.host = this.getInetAddress().getHostName();
      }

      return this.host;
   }

   synchronized String getRawHostname() {
      return this.rawHostname;
   }

   public synchronized void setHost(String var1) {
      this.host = var1;
      this.rawHostname = var1;
   }

   public synchronized InputStream getInputStream() throws IOException {
      if (this.isClosed()) {
         throw new SocketException("Socket is closed");
      } else if (this.connectionState == 0) {
         throw new SocketException("Socket is not connected");
      } else {
         return this.input;
      }
   }

   public synchronized OutputStream getOutputStream() throws IOException {
      if (this.isClosed()) {
         throw new SocketException("Socket is closed");
      } else if (this.connectionState == 0) {
         throw new SocketException("Socket is not connected");
      } else {
         return this.output;
      }
   }

   public SSLSession getSession() {
      if (this.getConnectionState() == 1) {
         try {
            this.startHandshake(false);
         } catch (IOException var3) {
            if (debug != null && Debug.isOn("handshake")) {
               System.out.println(threadName() + ", IOException in getSession():  " + var3);
            }
         }
      }

      synchronized(this) {
         return this.sess;
      }
   }

   public synchronized SSLSession getHandshakeSession() {
      return this.handshakeSession;
   }

   synchronized void setHandshakeSession(SSLSessionImpl var1) {
      this.handshakeSession = var1;
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
         System.out.println("setEnabledCipherSuites3");
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
            System.out.println("setEnabledProtocols2 protocols[" + var2 + "]=" + var1[var2]);
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

   public void setSoTimeout(int var1) throws SocketException {
      if (debug != null && Debug.isOn("ssl")) {
         System.out.println(threadName() + ", setSoTimeout(" + var1 + ") called");
      }

      if (this.self == this) {
         super.setSoTimeout(var1);
      } else {
         this.self.setSoTimeout(var1);
      }

   }

   public synchronized void addHandshakeCompletedListener(HandshakeCompletedListener var1) {
      if (var1 == null) {
         throw new IllegalArgumentException("listener is null");
      } else {
         if (this.handshakeListeners == null) {
            this.handshakeListeners = new HashMap(4);
         }

         this.handshakeListeners.put(var1, AccessController.getContext());
      }
   }

   public synchronized void removeHandshakeCompletedListener(HandshakeCompletedListener var1) {
      if (this.handshakeListeners == null) {
         throw new IllegalArgumentException("no listeners");
      } else if (this.handshakeListeners.remove(var1) == null) {
         throw new IllegalArgumentException("listener not registered");
      } else {
         if (this.handshakeListeners.isEmpty()) {
            this.handshakeListeners = null;
         }

      }
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
      StringBuffer var1 = new StringBuffer(80);
      var1.append(Integer.toHexString(this.hashCode()));
      var1.append("[");
      var1.append(this.sess.getCipherSuite());
      var1.append(": ");
      if (this.self == this) {
         var1.append(super.toString());
      } else {
         var1.append(this.self.toString());
      }

      var1.append("]");
      return var1.toString();
   }

   private static class NotifyHandshakeThread extends Thread {
      private Set<Entry<HandshakeCompletedListener, AccessControlContext>> targets;
      private HandshakeCompletedEvent event;

      NotifyHandshakeThread(Set<Entry<HandshakeCompletedListener, AccessControlContext>> var1, HandshakeCompletedEvent var2) {
         super("HandshakeCompletedNotify-Thread");
         this.targets = var1;
         this.event = var2;
      }

      public void run() {
         Iterator var2 = this.targets.iterator();

         while(var2.hasNext()) {
            Entry var1 = (Entry)var2.next();
            final HandshakeCompletedListener var3 = (HandshakeCompletedListener)var1.getKey();
            AccessControlContext var4 = (AccessControlContext)var1.getValue();
            AccessController.doPrivileged(new PrivilegedAction<Void>() {
               public Void run() {
                  var3.handshakeCompleted(NotifyHandshakeThread.this.event);
                  return null;
               }
            }, var4);
         }

      }
   }
}
