package cn.gmssl.sun.security.ssl;

import cn.gmssl.jsse.provider.GMConf;
import cn.gmssl.sun.security.internal.interfaces.TlsMasterSecret;
import cn.gmssl.sun.security.internal.spec.TlsKeyMaterialParameterSpec;
import cn.gmssl.sun.security.internal.spec.TlsKeyMaterialSpec;
import cn.gmssl.sun.security.internal.spec.TlsMasterSecretParameterSpec;
import java.io.IOException;
import java.io.PrintStream;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.ProviderException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.Set;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLKeyException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLProtocolException;
import sun.misc.HexDumpEncoder;

abstract class Handshaker {
   public StringBuilder sb = new StringBuilder();
   ProtocolVersion protocolVersion;
   ProtocolVersion activeProtocolVersion;
   boolean secureRenegotiation;
   byte[] clientVerifyData;
   byte[] serverVerifyData;
   boolean isInitialHandshake;
   private ProtocolList enabledProtocols;
   private CipherSuiteList enabledCipherSuites;
   String identificationProtocol;
   private AlgorithmConstraints algorithmConstraints = null;
   Collection<SignatureAndHashAlgorithm> localSupportedSignAlgs;
   Collection<SignatureAndHashAlgorithm> peerSupportedSignAlgs;
   private ProtocolList activeProtocols;
   private CipherSuiteList activeCipherSuites;
   private boolean isClient;
   private boolean needCertVerify;
   SSLSocketImpl conn = null;
   SSLEngineImpl engine = null;
   HandshakeHash handshakeHash;
   HandshakeInStream input;
   HandshakeOutStream output;
   int state;
   SSLContextImpl sslContext;
   RandomCookie clnt_random;
   RandomCookie svr_random;
   SSLSessionImpl session;
   CipherSuite cipherSuite;
   CipherSuite.KeyExchange keyExchange;
   boolean resumingSession;
   boolean enableNewSession;
   private SecretKey clntWriteKey;
   private SecretKey svrWriteKey;
   private IvParameterSpec clntWriteIV;
   private IvParameterSpec svrWriteIV;
   private SecretKey clntMacSecret;
   private SecretKey svrMacSecret;
   private volatile boolean taskDelegated = false;
   private volatile Handshaker.DelegatedTask delegatedTask = null;
   private volatile Exception thrown = null;
   private Object thrownLock = new Object();
   static final Debug debug = Debug.getInstance("ssl");
   static final boolean allowUnsafeRenegotiation = Debug.getBooleanProperty("sun.security.ssl.allowUnsafeRenegotiation", false);
   static final boolean allowLegacyHelloMessages = Debug.getBooleanProperty("sun.security.ssl.allowLegacyHelloMessages", true);
   boolean invalidated;

   Handshaker(SSLSocketImpl var1, SSLContextImpl var2, ProtocolList var3, boolean var4, boolean var5, ProtocolVersion var6, boolean var7, boolean var8, byte[] var9, byte[] var10) {
      this.conn = var1;
      this.init(var2, var3, var4, var5, var6, var7, var8, var9, var10);
   }

   Handshaker(SSLEngineImpl var1, SSLContextImpl var2, ProtocolList var3, boolean var4, boolean var5, ProtocolVersion var6, boolean var7, boolean var8, byte[] var9, byte[] var10) {
      this.engine = var1;
      this.init(var2, var3, var4, var5, var6, var7, var8, var9, var10);
   }

   private void init(SSLContextImpl var1, ProtocolList var2, boolean var3, boolean var4, ProtocolVersion var5, boolean var6, boolean var7, byte[] var8, byte[] var9) {
      if (debug != null && Debug.isOn("handshake")) {
         System.out.println("Allow unsafe renegotiation: " + allowUnsafeRenegotiation + "\nAllow legacy hello messages: " + allowLegacyHelloMessages + "\nIs initial handshake: " + var6 + "\nIs secure renegotiation: " + var7);
      }

      this.sslContext = var1;
      this.isClient = var4;
      this.needCertVerify = var3;
      this.activeProtocolVersion = var5;
      this.isInitialHandshake = var6;
      this.secureRenegotiation = var7;
      this.clientVerifyData = var8;
      this.serverVerifyData = var9;
      this.enableNewSession = true;
      this.invalidated = false;
      this.setCipherSuite(CipherSuite.C_NULL);
      this.setEnabledProtocols(var2);
      if (this.conn != null) {
         this.algorithmConstraints = new SSLAlgorithmConstraints(this.conn, true);
      } else {
         this.algorithmConstraints = new SSLAlgorithmConstraints(this.engine, true);
      }

      this.state = -2;
   }

   void fatalSE(byte var1, String var2) throws IOException {
      this.fatalSE(var1, var2, (Throwable)null);
   }

   void fatalSE(byte var1, Throwable var2) throws IOException {
      this.fatalSE(var1, (String)null, var2);
   }

   void fatalSE(byte var1, String var2, Throwable var3) throws IOException {
      if (this.conn != null) {
         this.conn.fatal(var1, var2, var3);
      } else {
         this.engine.fatal(var1, var2, var3);
      }

   }

   void warningSE(byte var1) {
      if (this.conn != null) {
         this.conn.warning(var1);
      } else {
         this.engine.warning(var1);
      }

   }

   String getRawHostnameSE() {
      return this.conn != null ? this.conn.getRawHostname() : this.engine.getPeerHost();
   }

   String getHostSE() {
      return this.conn != null ? this.conn.getHost() : this.engine.getPeerHost();
   }

   String getHostAddressSE() {
      return this.conn != null ? this.conn.getInetAddress().getHostAddress() : this.engine.getPeerHost();
   }

   boolean isLoopbackSE() {
      return this.conn != null ? this.conn.getInetAddress().isLoopbackAddress() : false;
   }

   int getPortSE() {
      return this.conn != null ? this.conn.getPort() : this.engine.getPeerPort();
   }

   int getLocalPortSE() {
      return this.conn != null ? this.conn.getLocalPort() : -1;
   }

   AccessControlContext getAccSE() {
      return this.conn != null ? this.conn.getAcc() : this.engine.getAcc();
   }

   private void setVersionSE(ProtocolVersion var1) {
      if (this.conn != null) {
         this.conn.setVersion(var1);
      } else {
         this.engine.setVersion(var1);
      }

   }

   void setVersion(ProtocolVersion var1) {
      this.protocolVersion = var1;
      this.setVersionSE(var1);
      this.output.r.setVersion(var1);
   }

   void setEnabledProtocols(ProtocolList var1) {
      this.activeCipherSuites = null;
      this.activeProtocols = null;
      this.enabledProtocols = var1;
   }

   void setEnabledCipherSuites(CipherSuiteList var1) {
      if (GMConf.debug) {
         System.out.println("setEnabledCipherSuites1 enabledCipherSuites=" + var1);
      }

      this.activeCipherSuites = null;
      this.activeProtocols = null;
      this.enabledCipherSuites = var1;
   }

   void setAlgorithmConstraints(AlgorithmConstraints var1) {
      this.activeCipherSuites = null;
      this.activeProtocols = null;
      this.algorithmConstraints = new SSLAlgorithmConstraints(var1);
      this.localSupportedSignAlgs = null;
   }

   Collection<SignatureAndHashAlgorithm> getLocalSupportedSignAlgs() {
      if (this.localSupportedSignAlgs == null) {
         this.localSupportedSignAlgs = SignatureAndHashAlgorithm.getSupportedAlgorithms(this.algorithmConstraints);
      }

      return this.localSupportedSignAlgs;
   }

   void setPeerSupportedSignAlgs(Collection<SignatureAndHashAlgorithm> var1) {
      this.peerSupportedSignAlgs = new ArrayList(var1);
   }

   Collection<SignatureAndHashAlgorithm> getPeerSupportedSignAlgs() {
      return this.peerSupportedSignAlgs;
   }

   void setIdentificationProtocol(String var1) {
      this.identificationProtocol = var1;
   }

   void activate(ProtocolVersion var1) throws IOException {
      if (this.activeProtocols == null) {
         this.activeProtocols = this.getActiveProtocols();
      }

      if (!this.activeProtocols.collection().isEmpty() && this.activeProtocols.max.v != ProtocolVersion.NONE.v) {
         if (this.activeCipherSuites == null) {
            this.activeCipherSuites = this.getActiveCipherSuites();
         }

         if (this.activeCipherSuites.collection().isEmpty()) {
            throw new SSLHandshakeException("No appropriate cipher suite");
         } else {
            if (!this.isInitialHandshake) {
               this.protocolVersion = this.activeProtocolVersion;
            } else {
               this.protocolVersion = this.activeProtocols.max;
            }

            if (var1 == null || var1.v == ProtocolVersion.NONE.v) {
               var1 = this.activeProtocols.helloVersion;
            }

            Set var2 = SignatureAndHashAlgorithm.getHashAlgorithmNames(this.getLocalSupportedSignAlgs());
            this.handshakeHash = new HandshakeHash(!this.isClient, this.needCertVerify, var2);
            this.input = new HandshakeInStream(this.handshakeHash);
            if (this.conn != null) {
               this.output = new HandshakeOutStream(this.protocolVersion, var1, this.handshakeHash, this.conn);
               this.conn.getAppInputStream().r.setHandshakeHash(this.handshakeHash);
               this.conn.getAppInputStream().r.setHelloVersion(var1);
               this.conn.getAppOutputStream().r.setHelloVersion(var1);
            } else {
               this.output = new HandshakeOutStream(this.protocolVersion, var1, this.handshakeHash, this.engine);
               this.engine.inputRecord.setHandshakeHash(this.handshakeHash);
               this.engine.inputRecord.setHelloVersion(var1);
               this.engine.outputRecord.setHelloVersion(var1);
            }

            this.state = -1;
         }
      } else {
         throw new SSLHandshakeException("No appropriate protocol");
      }
   }

   void setCipherSuite(CipherSuite var1) {
      this.cipherSuite = var1;
      this.keyExchange = var1.keyExchange;
   }

   boolean isNegotiable(CipherSuite var1) {
      if (this.activeCipherSuites == null) {
         this.activeCipherSuites = this.getActiveCipherSuites();
      }

      return this.activeCipherSuites.contains(var1) && var1.isNegotiable();
   }

   boolean isNegotiable(ProtocolVersion var1) {
      if (this.activeProtocols == null) {
         this.activeProtocols = this.getActiveProtocols();
      }

      return this.activeProtocols.contains(var1);
   }

   ProtocolVersion selectProtocolVersion(ProtocolVersion var1) {
      if (this.activeProtocols == null) {
         this.activeProtocols = this.getActiveProtocols();
      }

      return this.activeProtocols.selectProtocolVersion(var1);
   }

   CipherSuiteList getActiveCipherSuites() {
      if (this.activeCipherSuites == null) {
         if (this.activeProtocols == null) {
            this.activeProtocols = this.getActiveProtocols();
         }

         ArrayList var1 = new ArrayList();
         if (!this.activeProtocols.collection().isEmpty() && this.activeProtocols.min.v != ProtocolVersion.NONE.v) {
            Iterator var3 = this.enabledCipherSuites.collection().iterator();

            label51:
            while(true) {
               while(true) {
                  if (!var3.hasNext()) {
                     break label51;
                  }

                  CipherSuite var2 = (CipherSuite)var3.next();
                  if (GMConf.debug) {
                     System.out.println("enabledCipherSuites suite=" + var2);
                  }

                  if (var2.obsoleted > this.activeProtocols.min.v && var2.supported <= this.activeProtocols.max.v) {
                     if (this.algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), var2.name, (AlgorithmParameters)null)) {
                        if (GMConf.debug) {
                           System.out.println("enabledCipherSuites suite add=" + var2);
                        }

                        var1.add(var2);
                     } else if (GMConf.debug) {
                        System.out.println("enabledCipherSuites ignore=" + var2);
                     }
                  } else if (debug != null && Debug.isOn("verbose")) {
                     if (var2.obsoleted <= this.activeProtocols.min.v) {
                        System.out.println("Ignoring obsoleted cipher suite: " + var2);
                     } else {
                        System.out.println("Ignoring unsupported cipher suiteA: " + var2);
                     }
                  }
               }
            }
         }

         this.activeCipherSuites = new CipherSuiteList(var1);
      }

      return this.activeCipherSuites;
   }

   ProtocolList getActiveProtocols() {
      if (this.activeProtocols == null) {
         ArrayList var1 = new ArrayList(4);
         Iterator var3 = this.enabledProtocols.collection().iterator();

         while(var3.hasNext()) {
            ProtocolVersion var2 = (ProtocolVersion)var3.next();
            if (GMConf.debug) {
               System.out.println("getActiveProtocols protocol=" + var2);
            }

            boolean var4 = false;
            Iterator var6 = this.enabledCipherSuites.collection().iterator();

            label56:
            while(true) {
               while(true) {
                  if (!var6.hasNext()) {
                     break label56;
                  }

                  CipherSuite var5 = (CipherSuite)var6.next();
                  if (var5.isAvailable() && var5.obsoleted > var2.v && var5.supported <= var2.v) {
                     if (this.algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), var5.name, (AlgorithmParameters)null)) {
                        if (GMConf.debug) {
                           System.out.println("getActiveProtocols protocol add=" + var2);
                        }

                        var1.add(var2);
                        var4 = true;
                        break label56;
                     }

                     if (debug != null && Debug.isOn("verbose")) {
                        System.out.println("Ignoring disabled cipher suite: " + var5 + " for " + var2);
                     }
                  } else if (debug != null && Debug.isOn("verbose")) {
                     System.out.println("Ignoring unsupported cipher suiteB: " + var5 + " for " + var2);
                  }
               }
            }

            if (!var4 && debug != null && Debug.isOn("handshake")) {
               System.out.println("No available cipher suite for " + var2);
            }
         }

         this.activeProtocols = new ProtocolList(var1);
      }

      return this.activeProtocols;
   }

   void setEnableSessionCreation(boolean var1) {
      this.enableNewSession = var1;
   }

   CipherBox newReadCipher() throws NoSuchAlgorithmException {
      CipherSuite.BulkCipher var1 = this.cipherSuite.cipher;
      CipherBox var2;
      if (this.isClient) {
         var2 = var1.newCipher(this.protocolVersion, this.svrWriteKey, this.svrWriteIV, this.sslContext.getSecureRandom(), false);
         this.svrWriteKey = null;
         this.svrWriteIV = null;
      } else {
         var2 = var1.newCipher(this.protocolVersion, this.clntWriteKey, this.clntWriteIV, this.sslContext.getSecureRandom(), false);
         this.clntWriteKey = null;
         this.clntWriteIV = null;
      }

      return var2;
   }

   CipherBox newWriteCipher() throws NoSuchAlgorithmException {
      CipherSuite.BulkCipher var1 = this.cipherSuite.cipher;
      CipherBox var2;
      if (this.isClient) {
         var2 = var1.newCipher(this.protocolVersion, this.clntWriteKey, this.clntWriteIV, this.sslContext.getSecureRandom(), true);
         this.clntWriteKey = null;
         this.clntWriteIV = null;
      } else {
         var2 = var1.newCipher(this.protocolVersion, this.svrWriteKey, this.svrWriteIV, this.sslContext.getSecureRandom(), true);
         this.svrWriteKey = null;
         this.svrWriteIV = null;
      }

      return var2;
   }

   MAC newReadMAC() throws NoSuchAlgorithmException, InvalidKeyException {
      CipherSuite.MacAlg var1 = this.cipherSuite.macAlg;
      MAC var2;
      if (this.isClient) {
         var2 = var1.newMac(this.protocolVersion, this.svrMacSecret);
         this.svrMacSecret = null;
      } else {
         var2 = var1.newMac(this.protocolVersion, this.clntMacSecret);
         this.clntMacSecret = null;
      }

      return var2;
   }

   MAC newWriteMAC() throws NoSuchAlgorithmException, InvalidKeyException {
      CipherSuite.MacAlg var1 = this.cipherSuite.macAlg;
      MAC var2;
      if (this.isClient) {
         var2 = var1.newMac(this.protocolVersion, this.clntMacSecret);
         this.clntMacSecret = null;
      } else {
         var2 = var1.newMac(this.protocolVersion, this.svrMacSecret);
         this.svrMacSecret = null;
      }

      return var2;
   }

   boolean isDone() {
      return this.state == 20;
   }

   SSLSessionImpl getSession() {
      return this.session;
   }

   void setHandshakeSessionSE(SSLSessionImpl var1) {
      if (this.conn != null) {
         this.conn.setHandshakeSession(var1);
      } else {
         this.engine.setHandshakeSession(var1);
      }

   }

   boolean isSecureRenegotiation() {
      return this.secureRenegotiation;
   }

   byte[] getClientVerifyData() {
      return this.clientVerifyData;
   }

   byte[] getServerVerifyData() {
      return this.serverVerifyData;
   }

   void process_record(InputRecord var1, boolean var2) throws IOException {
      this.checkThrown();
      this.input.incomingRecord(var1);
      if (this.conn == null && !var2) {
         this.delegateTask(new PrivilegedExceptionAction<Void>() {
            public Void run() throws Exception {
               Handshaker.this.processLoop();
               return null;
            }
         });
      } else {
         this.processLoop();
      }

   }

   void processLoop() throws IOException {
      while(this.input.available() >= 4) {
         this.input.mark(4);
         byte var1 = (byte)this.input.getInt8();
         int var2 = this.input.getInt24();
         if (this.input.available() < var2) {
            this.input.reset();
            return;
         }

         if (var1 == 0) {
            this.input.reset();
            this.processMessage(var1, var2);
            this.input.ignore(4 + var2);
         } else {
            this.input.mark(var2);
            this.processMessage(var1, var2);
            this.input.digestNow();
         }
      }

   }

   boolean activated() {
      return this.state >= -1;
   }

   boolean started() {
      return this.state >= 0;
   }

   void kickstart() throws IOException {
      if (this.state < 0) {
         HandshakeMessage var1 = this.getKickstartMessage();
         if (debug != null && Debug.isOn("handshake")) {
            var1.print(System.out);
         }

         var1.write(this.output);
         this.output.flush();
         this.state = var1.messageType();
      }
   }

   abstract HandshakeMessage getKickstartMessage() throws SSLException;

   abstract void processMessage(byte var1, int var2) throws IOException;

   abstract void handshakeAlert(byte var1) throws SSLProtocolException;

   void sendChangeCipherSpec(HandshakeMessage.Finished var1, boolean var2) throws IOException {
      this.output.flush();
      Object var3;
      if (this.conn != null) {
         var3 = new OutputRecord((byte)20);
      } else {
         var3 = new EngineOutputRecord((byte)20, this.engine);
      }

      ((OutputRecord)var3).setVersion(this.protocolVersion);
      ((OutputRecord)var3).write(1);
      if (this.conn != null) {
         this.conn.writeLock.lock();

         try {
            this.conn.writeRecord((OutputRecord)var3);
            this.conn.changeWriteCiphers();
            if (debug != null && Debug.isOn("handshake")) {
               var1.print(System.out);
            }

            var1.write(this.output);
            this.output.flush();
         } finally {
            this.conn.writeLock.unlock();
         }
      } else {
         Object var4 = this.engine.writeLock;
         synchronized(this.engine.writeLock) {
            this.engine.writeRecord((EngineOutputRecord)var3);
            this.engine.changeWriteCiphers();
            if (debug != null && Debug.isOn("handshake")) {
               var1.print(System.out);
            }

            var1.write(this.output);
            if (var2) {
               this.output.setFinishedMsg();
            }

            this.output.flush();
         }
      }

   }

   void calculateKeys(SecretKey var1, ProtocolVersion var2) {
      SecretKey var3 = this.calculateMasterSecret(var1, var2);
      this.session.setMasterSecret(var3);
      this.calculateConnectionKeys(var3);
   }

   private SecretKey calculateMasterSecret(SecretKey var1, ProtocolVersion var2) {
      if (debug != null && Debug.isOn("keygen")) {
         HexDumpEncoder var3 = new HexDumpEncoder();
         System.out.println("SESSION KEYGEN:");
         System.out.println("PreMaster Secret:");
         printHex(var3, var1.getEncoded());
      }

      CipherSuite.PRF var4;
      String var16;
      if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
         var16 = "SunTls12MasterSecret";
         var4 = this.cipherSuite.prfAlg;
      } else {
         if (this.protocolVersion.major == 1) {
            var16 = "GBTlsMasterSecret";
         } else {
            var16 = "SunTlsMasterSecret";
         }

         var4 = CipherSuite.PRF.P_NONE;
      }

      String var5 = var4.getPRFHashAlg();
      int var6 = var4.getPRFHashLength();
      int var7 = var4.getPRFBlockSize();
      TlsMasterSecretParameterSpec var8 = new TlsMasterSecretParameterSpec(var1, this.protocolVersion.major, this.protocolVersion.minor, this.clnt_random.random_bytes, this.svr_random.random_bytes, var5, var6, var7);

      SecretKey var9;
      try {
         KeyGenerator var10 = JsseJce.getKeyGenerator(var16);
         var10.init(var8);
         var9 = var10.generateKey();
      } catch (GeneralSecurityException var15) {
         if (!var1.getAlgorithm().equals("TlsRsaPremasterSecret")) {
            throw new ProviderException(var15);
         }

         if (debug != null && Debug.isOn("handshake")) {
            System.out.println("RSA master secret generation error:");
            var15.printStackTrace(System.out);
            System.out.println("Generating new random premaster secret");
         }

         if (var2 != null) {
            var1 = RSAClientKeyExchange.generateDummySecret(var2);
         } else {
            var1 = RSAClientKeyExchange.generateDummySecret(this.protocolVersion);
         }

         return this.calculateMasterSecret(var1, (ProtocolVersion)null);
      }

      if (var2 != null && var9 instanceof TlsMasterSecret) {
         TlsMasterSecret var17 = (TlsMasterSecret)var9;
         int var11 = var17.getMajorVersion();
         int var12 = var17.getMinorVersion();
         if (var11 >= 0 && var12 >= 0) {
            ProtocolVersion var13 = ProtocolVersion.valueOf(var11, var12);
            boolean var14 = var13.v != var2.v;
            if (var14 && var2.v <= ProtocolVersion.TLS10.v) {
               var14 = var13.v != this.protocolVersion.v;
            }

            if (!var14) {
               return var9;
            } else {
               if (debug != null && Debug.isOn("handshake")) {
                  System.out.println("RSA PreMasterSecret version error: expected" + this.protocolVersion + " or " + var2 + ", decrypted: " + var13);
                  System.out.println("Generating new random premaster secret");
               }

               var1 = RSAClientKeyExchange.generateDummySecret(var2);
               return this.calculateMasterSecret(var1, (ProtocolVersion)null);
            }
         } else {
            return var9;
         }
      } else {
         return var9;
      }
   }

   void calculateConnectionKeys(SecretKey var1) {
      int var2 = this.cipherSuite.macAlg.size;
      boolean var3 = this.cipherSuite.exportable;
      CipherSuite.BulkCipher var4 = this.cipherSuite.cipher;
      int var5 = var3 ? var4.expandedKeySize : 0;
      String var6;
      CipherSuite.PRF var7;
      if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
         var6 = "SunTls12KeyMaterial";
         var7 = this.cipherSuite.prfAlg;
      } else {
         if (this.protocolVersion.major == 1) {
            var6 = "GBTlsKeyMaterial";
         } else {
            var6 = "SunTlsKeyMaterial";
         }

         var7 = CipherSuite.PRF.P_NONE;
      }

      String var8 = var7.getPRFHashAlg();
      int var9 = var7.getPRFHashLength();
      int var10 = var7.getPRFBlockSize();
      TlsKeyMaterialParameterSpec var11 = new TlsKeyMaterialParameterSpec(var1, this.protocolVersion.major, this.protocolVersion.minor, this.clnt_random.random_bytes, this.svr_random.random_bytes, var4.algorithm, var4.keySize, var5, var4.ivSize, var2, var8, var9, var10);

      try {
         KeyGenerator var12 = JsseJce.getKeyGenerator(var6);
         var12.init(var11);
         TlsKeyMaterialSpec var13 = (TlsKeyMaterialSpec)var12.generateKey();
         this.clntWriteKey = var13.getClientCipherKey();
         this.svrWriteKey = var13.getServerCipherKey();
         this.clntWriteIV = var13.getClientIv();
         this.svrWriteIV = var13.getServerIv();
         this.clntMacSecret = var13.getClientMacKey();
         this.svrMacSecret = var13.getServerMacKey();
      } catch (GeneralSecurityException var15) {
         throw new ProviderException(var15);
      }

      if (debug != null && Debug.isOn("keygen")) {
         PrintStream var16 = System.out;
         synchronized(System.out) {
            HexDumpEncoder var17 = new HexDumpEncoder();
            System.out.println("CONNECTION KEYGEN:");
            System.out.println("Client Nonce:");
            printHex(var17, this.clnt_random.random_bytes);
            System.out.println("Server Nonce:");
            printHex(var17, this.svr_random.random_bytes);
            System.out.println("Master Secret:");
            printHex(var17, var1.getEncoded());
            System.out.println("Client MAC write Secret:");
            printHex(var17, this.clntMacSecret.getEncoded());
            System.out.println("Server MAC write Secret:");
            printHex(var17, this.svrMacSecret.getEncoded());
            if (this.clntWriteKey != null) {
               System.out.println("Client write key:");
               printHex(var17, this.clntWriteKey.getEncoded());
               System.out.println("Server write key:");
               printHex(var17, this.svrWriteKey.getEncoded());
            } else {
               System.out.println("... no encryption keys used");
            }

            if (this.clntWriteIV != null) {
               System.out.println("Client write IV:");
               printHex(var17, this.clntWriteIV.getIV());
               System.out.println("Server write IV:");
               printHex(var17, this.svrWriteIV.getIV());
            } else if (this.protocolVersion.v >= ProtocolVersion.TLS11.v) {
               System.out.println("... no IV derived for this protocol");
            } else {
               System.out.println("... no IV used for this cipher");
            }

            System.out.flush();
         }
      }

   }

   private static void printHex(HexDumpEncoder var0, byte[] var1) {
      if (var1 == null) {
         System.out.println("(key bytes not available)");
      } else {
         try {
            var0.encodeBuffer(var1, System.out);
         } catch (IOException var3) {
            ;
         }
      }

   }

   static void throwSSLException(String var0, Throwable var1) throws SSLException {
      SSLException var2 = new SSLException(var0);
      var2.initCause(var1);
      throw var2;
   }

   private <T> void delegateTask(PrivilegedExceptionAction<T> var1) {
      this.delegatedTask = new Handshaker.DelegatedTask(var1);
      this.taskDelegated = false;
      this.thrown = null;
   }

   Handshaker.DelegatedTask getTask() {
      if (!this.taskDelegated) {
         this.taskDelegated = true;
         return this.delegatedTask;
      } else {
         return null;
      }
   }

   boolean taskOutstanding() {
      return this.delegatedTask != null;
   }

   void checkThrown() throws SSLException {
      Object var1 = this.thrownLock;
      synchronized(this.thrownLock) {
         if (this.thrown != null) {
            String var2 = this.thrown.getMessage();
            if (var2 == null) {
               var2 = "Delegated task threw Exception/Error";
            }

            Exception var3 = this.thrown;
            this.thrown = null;
            if (var3 instanceof RuntimeException) {
               throw (RuntimeException)(new RuntimeException(var2)).initCause(var3);
            } else if (var3 instanceof SSLHandshakeException) {
               throw (SSLHandshakeException)(new SSLHandshakeException(var2)).initCause(var3);
            } else if (var3 instanceof SSLKeyException) {
               throw (SSLKeyException)(new SSLKeyException(var2)).initCause(var3);
            } else if (var3 instanceof SSLPeerUnverifiedException) {
               throw (SSLPeerUnverifiedException)(new SSLPeerUnverifiedException(var2)).initCause(var3);
            } else if (var3 instanceof SSLProtocolException) {
               throw (SSLProtocolException)(new SSLProtocolException(var2)).initCause(var3);
            } else {
               throw (SSLException)(new SSLException(var2)).initCause(var3);
            }
         }
      }
   }

   class DelegatedTask<E> implements Runnable {
      private PrivilegedExceptionAction<E> pea;

      DelegatedTask(PrivilegedExceptionAction<E> var2) {
         this.pea = var2;
      }

      public void run() {
         SSLEngineImpl var1 = Handshaker.this.engine;
         synchronized(Handshaker.this.engine) {
            try {
               AccessController.doPrivileged(this.pea, Handshaker.this.engine.getAcc());
            } catch (PrivilegedActionException var3) {
               Handshaker.this.thrown = var3.getException();
            } catch (RuntimeException var4) {
               Handshaker.this.thrown = var4;
            }

            Handshaker.this.delegatedTask = null;
            Handshaker.this.taskDelegated = false;
         }
      }
   }
}
