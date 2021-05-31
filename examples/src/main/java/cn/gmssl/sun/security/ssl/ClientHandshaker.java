package cn.gmssl.sun.security.ssl;

import cn.gmssl.com.jsse.SM2CertUtil;
import cn.gmssl.crypto.impl.sm2.SM2Util;
import cn.gmssl.jsse.provider.GMConf;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.Subject;
import sun.net.util.IPAddressUtil;

final class ClientHandshaker extends Handshaker {
   private PublicKey sigServerKey = null;
   private PublicKey encServerKey = null;
   private PublicKey ephemeralServerKey;
   private BigInteger serverDH;
   private DHCrypt dh;
   private ECDHCrypt ecdh;
   private SM2Crypt sm2;
   private PrivateKey clientPrivateKey = null;
   private PublicKey clientPublicKey = null;
   private PrivateKey encClientPrivateKey = null;
   private PublicKey encClientPublicKey = null;
   private byte[] idLocal = null;
   private byte[] idRemote = null;
   private byte[] encIdLocal = null;
   private byte[] encIdRemote = null;
   private HandshakeMessage.CertificateRequest certRequest;
   private boolean serverKeyExchangeReceived;
   private ProtocolVersion maxProtocolVersion;
   private static final boolean enableSNIExtension = Debug.getBooleanProperty("jsse.enableSNIExtension", true);
   // $FF: synthetic field
   private static int[] $SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange;

   ClientHandshaker(SSLSocketImpl var1, SSLContextImpl var2, ProtocolList var3, ProtocolVersion var4, boolean var5, boolean var6, byte[] var7, byte[] var8) {
      super(var1, var2, var3, true, true, var4, var5, var6, var7, var8);
   }

   ClientHandshaker(SSLEngineImpl var1, SSLContextImpl var2, ProtocolList var3, ProtocolVersion var4, boolean var5, boolean var6, byte[] var7, byte[] var8) {
      super(var1, var2, var3, true, true, var4, var5, var6, var7, var8);
   }

   void processMessage(byte var1, int var2) throws IOException {
      if (this.state > var1 && var1 != 0 && this.state != 1) {
         throw new SSLProtocolException("Handshake message sequence violation, " + var1);
      } else {
         label122:
         switch(var1) {
         case 0:
            this.serverHelloRequest(new HandshakeMessage.HelloRequest(this.input));
            break;
         case 2:
            this.serverHello(new HandshakeMessage.ServerHello(this.input, var2));
            break;
         case 11:
            if (this.keyExchange == CipherSuite.KeyExchange.K_DH_ANON || this.keyExchange == CipherSuite.KeyExchange.K_ECDH_ANON || this.keyExchange == CipherSuite.KeyExchange.K_KRB5 || this.keyExchange == CipherSuite.KeyExchange.K_KRB5_EXPORT) {
               this.fatalSE((byte)10, "unexpected server cert chain");
            }

            this.serverCertificate(new HandshakeMessage.CertificateMsg(this.input));
            this.sigServerKey = this.session.getPeerCertificates()[0].getPublicKey();
            this.idRemote = SM2Util.getId((X509Certificate)this.session.getPeerCertificates()[0], this.protocolVersion.minor);
            if (this.protocolVersion.major == 1 && this.protocolVersion.minor == 1) {
               this.encServerKey = this.session.getPeerCertificates()[1].getPublicKey();
               this.encIdRemote = SM2Util.getId((X509Certificate)this.session.getPeerCertificates()[1], this.protocolVersion.minor);
            }
            break;
         case 12:
            this.serverKeyExchangeReceived = true;
            switch($SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange()[this.keyExchange.ordinal()]) {
            case 2:
            case 4:
            case 5:
            case 9:
            case 10:
               throw new SSLProtocolException("Protocol violation: server sent a server key exchangemessage for key exchange " + this.keyExchange);
            case 3:
               if (this.sigServerKey == null) {
                  throw new SSLProtocolException("Server did not send certificate message");
               }

               if (!(this.sigServerKey instanceof RSAPublicKey)) {
                  throw new SSLProtocolException("Protocol violation: the certificate type must be appropriate for the selected cipher suite's key exchange algorithm");
               }

               if (JsseJce.getRSAKeyLength(this.sigServerKey) <= 512) {
                  throw new SSLProtocolException("Protocol violation: server sent a server key exchange message for key exchange " + this.keyExchange + " when the public key in the server certificate" + " is less than or equal to 512 bits in length");
               }

               try {
                  this.serverKeyExchange(new HandshakeMessage.RSA_ServerKeyExchange(this.input));
               } catch (GeneralSecurityException var10) {
                  throwSSLException("Server key", var10);
               }
               break label122;
            case 6:
            case 7:
               try {
                  this.serverKeyExchange(new HandshakeMessage.DH_ServerKeyExchange(this.input, this.sigServerKey, this.clnt_random.random_bytes, this.svr_random.random_bytes, var2, this.localSupportedSignAlgs, this.protocolVersion));
               } catch (GeneralSecurityException var9) {
                  throwSSLException("Server key", var9);
               }
               break label122;
            case 8:
               this.serverKeyExchange(new HandshakeMessage.DH_ServerKeyExchange(this.input, this.protocolVersion));
               break label122;
            case 11:
            case 12:
            case 13:
               try {
                  this.serverKeyExchange(new HandshakeMessage.ECDH_ServerKeyExchange(this.input, this.sigServerKey, this.clnt_random.random_bytes, this.svr_random.random_bytes, this.localSupportedSignAlgs, this.protocolVersion));
               } catch (GeneralSecurityException var8) {
                  throwSSLException("Server key", var8);
               }
               break label122;
            case 14:
               try {
                  this.gbServerKeyExchange(new HandshakeMessage.SM2_ServerKeyExchange(this.input, this.sigServerKey, this.clnt_random.random_bytes, this.svr_random.random_bytes, this.localSupportedSignAlgs, this.protocolVersion));
               } catch (GeneralSecurityException var6) {
                  throwSSLException("Server key", var6);
               }
               break label122;
            case 15:
               try {
                  ECCServerKeyExchange var11 = new ECCServerKeyExchange(this.input);
                  boolean var12 = false;
                  X509Certificate var5 = (X509Certificate)this.session.getPeerCertificates()[1];
                  var12 = var11.verify(this.sigServerKey, this.clnt_random, this.svr_random, var5);
                  if (!var12) {
                     this.fatalSE((byte)40, "server key exchange invalid");
                  }
               } catch (Exception var7) {
                  throwSSLException("Server key", var7);
               }
               break label122;
            case 16:
            case 17:
               throw new SSLProtocolException("unexpected receipt of server key exchange algorithm");
            default:
               throw new SSLProtocolException("unsupported key exchange algorithm = " + this.keyExchange);
            }
         case 13:
            if (this.keyExchange != CipherSuite.KeyExchange.K_DH_ANON && this.keyExchange != CipherSuite.KeyExchange.K_ECDH_ANON) {
               if (this.keyExchange == CipherSuite.KeyExchange.K_KRB5 || this.keyExchange == CipherSuite.KeyExchange.K_KRB5_EXPORT) {
                  throw new SSLHandshakeException("Client certificate requested for kerberos cipher suite.");
               }

               this.certRequest = new HandshakeMessage.CertificateRequest(this.input, this.protocolVersion);
               if (debug != null && Debug.isOn("handshake")) {
                  this.certRequest.print(System.out);
               }

               if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
                  Collection var3 = this.certRequest.getSignAlgorithms();
                  if (var3 == null || var3.isEmpty()) {
                     throw new SSLHandshakeException("No peer supported signature algorithms");
                  }

                  Collection var4 = SignatureAndHashAlgorithm.getSupportedAlgorithms(var3);
                  if (var4.isEmpty()) {
                     throw new SSLHandshakeException("No supported signature and hash algorithm in common");
                  }

                  this.setPeerSupportedSignAlgs(var4);
                  this.session.setPeerSupportedSignatureAlgorithms(var4);
               }
               break;
            }

            throw new SSLHandshakeException("Client authentication requested for anonymous cipher suite.");
         case 14:
            this.serverHelloDone(new HandshakeMessage.ServerHelloDone(this.input));
            break;
         case 20:
            this.serverFinished(new HandshakeMessage.Finished(this.protocolVersion, this.input, this.cipherSuite));
            break;
         default:
            throw new SSLProtocolException("Illegal client handshake msg, " + var1);
         }

         if (this.state < var1) {
            this.state = var1;
         }

      }
   }

   private void serverHelloRequest(HandshakeMessage.HelloRequest var1) throws IOException {
      if (debug != null && Debug.isOn("handshake")) {
         var1.print(System.out);
      }

      if (this.state < 1) {
         if (!this.secureRenegotiation && !allowUnsafeRenegotiation) {
            if (this.activeProtocolVersion.v >= ProtocolVersion.TLS10.v) {
               this.warningSE((byte)100);
               this.invalidated = true;
            } else {
               this.fatalSE((byte)40, "Renegotiation is not allowed");
            }
         } else {
            if (!this.secureRenegotiation && debug != null && Debug.isOn("handshake")) {
               System.out.println("Warning: continue with insecure renegotiation");
            }

            this.kickstart();
         }
      }

   }

   private void serverHello(HandshakeMessage.ServerHello var1) throws IOException {
      this.serverKeyExchangeReceived = false;
      if (debug != null && Debug.isOn("handshake")) {
         var1.print(System.out);
      }

      ProtocolVersion var2 = var1.protocolVersion;
      if (!this.isNegotiable(var2)) {
         throw new SSLHandshakeException("Server chose " + var2 + ", but that protocol version is not enabled or not supported " + "by the client.");
      } else {
         this.handshakeHash.protocolDetermined(var2);
         this.setVersion(var2);
         RenegotiationInfoExtension var3 = (RenegotiationInfoExtension)var1.extensions.get(ExtensionType.EXT_RENEGOTIATION_INFO);
         if (var3 != null) {
            if (this.isInitialHandshake) {
               if (!var3.isEmpty()) {
                  this.fatalSE((byte)40, "The renegotiation_info field is not empty");
               }

               this.secureRenegotiation = true;
            } else {
               if (!this.secureRenegotiation) {
                  this.fatalSE((byte)40, "Unexpected renegotiation indication extension");
               }

               byte[] var4 = new byte[this.clientVerifyData.length + this.serverVerifyData.length];
               System.arraycopy(this.clientVerifyData, 0, var4, 0, this.clientVerifyData.length);
               System.arraycopy(this.serverVerifyData, 0, var4, this.clientVerifyData.length, this.serverVerifyData.length);
               if (!Arrays.equals(var4, var3.getRenegotiatedConnection())) {
                  this.fatalSE((byte)40, "Incorrect verify data in ServerHello renegotiation_info message");
               }
            }
         } else if (this.isInitialHandshake) {
            if (!allowLegacyHelloMessages) {
               this.fatalSE((byte)40, "Failed to negotiate the use of secure renegotiation");
            }

            this.secureRenegotiation = false;
            if (debug != null && Debug.isOn("handshake")) {
               System.out.println("Warning: No renegotiation indication extension in ServerHello");
            }
         } else if (this.secureRenegotiation) {
            this.fatalSE((byte)40, "No renegotiation indication extension");
         }

         this.svr_random = var1.svr_random;
         if (!this.isNegotiable(var1.cipherSuite)) {
            this.fatalSE((byte)47, "Server selected improper ciphersuite " + var1.cipherSuite);
         }

         this.setCipherSuite(var1.cipherSuite);
         if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
            this.handshakeHash.setFinishedAlg(this.cipherSuite.prfAlg.getPRFHashAlg());
         }

         if (var1.compression_method != 0) {
            this.fatalSE((byte)47, "compression type not supported, " + var1.compression_method);
         }

         if (this.session != null) {
            if (this.session.getSessionId().equals(var1.sessionId)) {
               CipherSuite var10 = this.session.getSuite();
               if (this.cipherSuite != var10) {
                  throw new SSLProtocolException("Server returned wrong cipher suite for session");
               }

               ProtocolVersion var5 = this.session.getProtocolVersion();
               if (this.protocolVersion != var5) {
                  throw new SSLProtocolException("Server resumed session with wrong protocol version");
               }

               if (var10.keyExchange == CipherSuite.KeyExchange.K_KRB5 || var10.keyExchange == CipherSuite.KeyExchange.K_KRB5_EXPORT) {
                  Principal var6 = this.session.getLocalPrincipal();
                  Subject var7 = null;

                  try {
                     var7 = (Subject)AccessController.doPrivileged(new PrivilegedExceptionAction<Subject>() {
                        public Subject run() throws Exception {
                           return Krb5Helper.getClientSubject(ClientHandshaker.this.getAccSE());
                        }
                     });
                  } catch (PrivilegedActionException var9) {
                     var7 = null;
                     if (debug != null && Debug.isOn("session")) {
                        System.out.println("Attempt to obtain subject failed!");
                     }
                  }

                  if (var7 == null) {
                     if (debug != null && Debug.isOn("session")) {
                        System.out.println("Kerberos credentials are not present in the current Subject; check if  javax.security.auth.useSubjectAsCreds system property has been set to false");
                     }

                     throw new SSLProtocolException("Server resumed session with no subject");
                  }

                  Set var8 = var7.getPrincipals(Principal.class);
                  if (!var8.contains(var6)) {
                     throw new SSLProtocolException("Server resumed session with wrong subject identity");
                  }

                  if (debug != null && Debug.isOn("session")) {
                     System.out.println("Subject identity is same");
                  }
               }

               this.resumingSession = true;
               this.state = 19;
               this.calculateConnectionKeys(this.session.getMasterSecret());
               if (debug != null && Debug.isOn("session")) {
                  System.out.println("%% Server resumed " + this.session);
               }
            } else {
               this.session = null;
               if (!this.enableNewSession) {
                  throw new SSLException("New session creation is disabled");
               }
            }
         }

         if (this.resumingSession && this.session != null) {
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
               this.handshakeHash.setCertificateVerifyAlg((String)null);
            }

            this.setHandshakeSessionSE(this.session);
         } else {
            Iterator var12 = var1.extensions.list().iterator();

            while(var12.hasNext()) {
               HelloExtension var11 = (HelloExtension)var12.next();
               ExtensionType var13 = var11.type;
               if (var13 != ExtensionType.EXT_ELLIPTIC_CURVES && var13 != ExtensionType.EXT_EC_POINT_FORMATS && var13 != ExtensionType.EXT_SERVER_NAME && var13 != ExtensionType.EXT_RENEGOTIATION_INFO) {
                  this.fatalSE((byte)110, "Server sent an unsupported extension: " + var13);
               }
            }

            this.session = new SSLSessionImpl(this.protocolVersion, this.cipherSuite, this.getLocalSupportedSignAlgs(), var1.sessionId, this.getHostSE(), this.getPortSE());
            this.setHandshakeSessionSE(this.session);
            if (debug != null && Debug.isOn("handshake")) {
               System.out.println("** " + this.cipherSuite);
            }

         }
      }
   }

   private void serverKeyExchange(HandshakeMessage.RSA_ServerKeyExchange var1) throws IOException, GeneralSecurityException {
      if (debug != null && Debug.isOn("handshake")) {
         var1.print(System.out);
      }

      if (!var1.verify(this.sigServerKey, this.clnt_random, this.svr_random)) {
         this.fatalSE((byte)40, "server key exchange invalid");
      }

      this.ephemeralServerKey = var1.getPublicKey();
   }

   private void serverKeyExchange(HandshakeMessage.DH_ServerKeyExchange var1) throws IOException {
      if (debug != null && Debug.isOn("handshake")) {
         var1.print(System.out);
      }

      this.dh = new DHCrypt(var1.getModulus(), var1.getBase(), this.sslContext.getSecureRandom());
      this.serverDH = var1.getServerPublicKey();
   }

   private void serverKeyExchange(HandshakeMessage.ECDH_ServerKeyExchange var1) throws IOException {
      if (debug != null && Debug.isOn("handshake")) {
         var1.print(System.out);
      }

      ECPublicKey var2 = var1.getPublicKey();
      this.ecdh = new ECDHCrypt(var2.getParams(), this.sslContext.getSecureRandom());
      this.ephemeralServerKey = var2;
   }

   private void gbServerKeyExchange(HandshakeMessage.SM2_ServerKeyExchange var1) throws IOException {
      if (debug != null && Debug.isOn("handshake")) {
         var1.print(System.out);
      }

      ECPublicKey var2 = var1.getPublicKey();
      this.ephemeralServerKey = var2;
   }

   private void serverHelloDone(HandshakeMessage.ServerHelloDone var1) throws IOException {
      if (debug != null && Debug.isOn("handshake")) {
         var1.print(System.out);
      }

      this.input.digestNow();
      PrivateKey var2 = null;
      if (debug != null && Debug.isOn("handshake")) {
         System.out.println("certRequest=" + this.certRequest);
      }

      if (this.certRequest != null) {
         X509ExtendedKeyManager var3 = this.sslContext.getX509KeyManager();
         ArrayList var4 = new ArrayList(4);

         for(int var5 = 0; var5 < this.certRequest.types.length; ++var5) {
            String var6;
            switch(this.certRequest.types[var5]) {
            case 1:
               var6 = "RSA";
               break;
            case 2:
               var6 = "DSA";
               break;
            case 3:
            case 4:
            case 5:
            case 6:
            case 65:
            case 66:
            default:
               var6 = null;
               break;
            case 64:
               var6 = JsseJce.isEcAvailable() ? "EC" : null;
            }

            if (var6 != null && !var4.contains(var6)) {
               var4.add(var6);
            }
         }

         String var19 = null;
         int var24 = var4.size();
         if (var24 != 0) {
            String[] var7 = (String[])var4.toArray(new String[var24]);
            if (this.conn != null) {
               var19 = var3.chooseClientAlias(var7, this.certRequest.getAuthorities(), this.conn);
            } else {
               var19 = var3.chooseEngineClientAlias(var7, this.certRequest.getAuthorities(), this.engine);
            }
         }

         HandshakeMessage.CertificateMsg var22 = null;
         PrivateKey var8 = null;
         PrivateKey var9 = null;
         if (var19 != null) {
            X509Certificate[] var10 = null;
            if (this.protocolVersion.major == 1 && this.protocolVersion.minor == 1) {
               int var11 = var19.indexOf(58);
               if (var11 == -1) {
                  if (GMConf.debug) {
                     System.out.println("alias=" + var19);
                  }

                  throw new RuntimeException("gb tls 1.1 must use double certificate");
               }

               String var12 = var19.substring(0, var11);
               String var13 = var19.substring(var11 + 1);
               if (GMConf.debug) {
                  System.out.println("alias=" + var19 + ",alias1=" + var12 + ",alias2=" + var13);
               }

               X509Certificate[] var14 = var3.getCertificateChain(var12);
               if (var14 == null || var14.length == 0) {
                  throw new RuntimeException("certificate " + var12 + " cannot found");
               }

               X509Certificate[] var15 = var3.getCertificateChain(var13);
               if (var15 == null || var15.length == 0) {
                  throw new RuntimeException("certificate " + var12 + " cannot found");
               }

               if (SM2CertUtil.signCert(var14[0]) && SM2CertUtil.encryptCert(var15[0])) {
                  var10 = new X509Certificate[]{var14[0], var15[0]};
                  var8 = var3.getPrivateKey(var12);
                  var9 = var3.getPrivateKey(var13);
                  if (GMConf.debug) {
                     System.out.println("alias_1=" + var19 + ",signPrivateKey=" + var8 + ",encPrivateKey=" + var9);
                  }
               } else {
                  var10 = new X509Certificate[]{var15[0], var14[0]};
                  var8 = var3.getPrivateKey(var13);
                  var9 = var3.getPrivateKey(var12);
                  if (GMConf.debug) {
                     System.out.println("alias_2=" + var19 + ",signPrivateKey=" + var8 + ",encPrivateKey=" + var9);
                  }
               }
            } else {
               var10 = var3.getCertificateChain(var19);
               if (GMConf.debug) {
                  System.out.println("aliasxxx=" + var19 + ",certs=" + var10);
               }
            }

            if (GMConf.debug) {
               System.out.println("xxxcerts=" + var10);
            }

            if (var10 != null && var10.length != 0) {
               if (GMConf.debug) {
                  System.out.println("xxxcerts.length=" + var10.length);
               }

               PublicKey var30 = var10[0].getPublicKey();
               this.clientPublicKey = var30;
               if (this.protocolVersion.major != 1 && var30 instanceof ECPublicKey) {
                  ECParameterSpec var31 = ((ECPublicKey)var30).getParams();
                  int var32 = SupportedEllipticCurvesExtension.getCurveIndex(var31);
                  if (!SupportedEllipticCurvesExtension.isSupported(var32)) {
                     var30 = null;
                  }
               }

               if (GMConf.debug) {
                  System.out.println("aliasxxx=" + var19 + ",publicKey=" + var30 + ",signPrivateKey=" + var8);
               }

               if (var30 != null) {
                  var22 = new HandshakeMessage.CertificateMsg(var10);
                  if (var8 != null) {
                     var2 = var8;
                  } else {
                     var2 = var3.getPrivateKey(var19);
                  }

                  this.clientPrivateKey = var2;
                  this.session.setLocalPrivateKey(var2);
                  this.session.setLocalCertificates(var10);
                  if (this.protocolVersion.major == 1 && this.protocolVersion.minor == 1) {
                     this.encClientPrivateKey = var9;
                     this.encClientPublicKey = var10[1].getPublicKey();
                     this.idLocal = SM2Util.getId(var10[0], this.protocolVersion.minor);
                     this.encIdLocal = SM2Util.getId(var10[1], this.protocolVersion.minor);
                  }
               }
            }
         }

         if (var22 == null) {
            if (this.protocolVersion.v >= ProtocolVersion.TLS10.v) {
               var22 = new HandshakeMessage.CertificateMsg(new X509Certificate[0]);
            } else {
               this.warningSE((byte)41);
            }
         }

         if (var22 != null) {
            if (debug != null && Debug.isOn("handshake")) {
               var22.print(System.out);
            }

            var22.write(this.output);
         }
      }

      Object var17;
      String var28;
      switch($SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange()[this.keyExchange.ordinal()]) {
      case 2:
      case 3:
         if (this.sigServerKey == null) {
            throw new SSLProtocolException("Server did not send certificate message");
         }

         if (!(this.sigServerKey instanceof RSAPublicKey)) {
            throw new SSLProtocolException("Server certificate does not include an RSA key");
         }

         PublicKey var18;
         if (this.keyExchange == CipherSuite.KeyExchange.K_RSA) {
            var18 = this.sigServerKey;
         } else if (JsseJce.getRSAKeyLength(this.sigServerKey) <= 512) {
            var18 = this.sigServerKey;
         } else {
            if (this.ephemeralServerKey == null) {
               throw new SSLProtocolException("Server did not send a RSA_EXPORT Server Key Exchange message");
            }

            var18 = this.ephemeralServerKey;
         }

         var17 = new RSAClientKeyExchange(this.protocolVersion, this.maxProtocolVersion, this.sslContext.getSecureRandom(), var18);
         break;
      case 4:
      case 5:
         var17 = new DHClientKeyExchange();
         break;
      case 6:
      case 7:
      case 8:
         if (this.dh == null) {
            throw new SSLProtocolException("Server did not send a DH Server Key Exchange message");
         }

         var17 = new DHClientKeyExchange(this.dh.getPublicKey());
         break;
      case 9:
      case 10:
         if (this.sigServerKey == null) {
            throw new SSLProtocolException("Server did not send certificate message");
         }

         if (!(this.sigServerKey instanceof ECPublicKey)) {
            throw new SSLProtocolException("Server certificate does not include an EC key");
         }

         ECParameterSpec var26 = ((ECPublicKey)this.sigServerKey).getParams();
         this.ecdh = new ECDHCrypt(var26, this.sslContext.getSecureRandom());
         var17 = new ECDHClientKeyExchange(this.ecdh.getPublicKey());
         break;
      case 11:
      case 12:
      case 13:
         if (this.ecdh == null) {
            throw new SSLProtocolException("Server did not send a ECDH Server Key Exchange message");
         }

         var17 = new ECDHClientKeyExchange(this.ecdh.getPublicKey());
         break;
      case 14:
         if (this.protocolVersion.major != 1) {
            throw new RuntimeException("gb tls protocol version major must be 1");
         }

         if (this.protocolVersion.minor == 0) {
            this.ecdh = new ECDHCrypt(((ECPublicKey)this.ephemeralServerKey).getParams(), this.sslContext.getSecureRandom());
            var17 = new ECDHClientKeyExchange(this.ecdh.getPublicKey());
         } else {
            if (this.protocolVersion.minor != 1) {
               throw new RuntimeException("unsupported protocol version");
            }

            this.sm2 = new SM2Crypt(this.encClientPublicKey, this.encClientPrivateKey, this.sslContext.getSecureRandom(), false);
            var17 = new SM2ClientKeyExchange(this.sm2.getRPointEncoded());
         }
         break;
      case 15:
         if (this.encServerKey == null) {
            throw new SSLProtocolException("Server did not send certificate message");
         }

         if (!(this.encServerKey instanceof ECPublicKey)) {
            throw new SSLProtocolException("Server certificate does not include an RSA key");
         }

         PublicKey var21 = this.encServerKey;
         var17 = new ECCClientKeyExchange(this.protocolVersion, this.maxProtocolVersion, this.sslContext.getSecureRandom(), var21);
         break;
      case 16:
      case 17:
         var28 = this.getHostSE();
         if (var28 == null) {
            throw new IOException("Hostname is required to use Kerberos cipher suites");
         }

         KerberosClientKeyExchange var29 = new KerberosClientKeyExchange(var28, this.isLoopbackSE(), this.getAccSE(), this.protocolVersion, this.sslContext.getSecureRandom());
         this.session.setPeerPrincipal(var29.getPeerPrincipal());
         this.session.setLocalPrincipal(var29.getLocalPrincipal());
         var17 = var29;
         break;
      default:
         throw new RuntimeException("Unsupported key exchange: " + this.keyExchange);
      }

      if (debug != null && Debug.isOn("handshake")) {
         ((HandshakeMessage)var17).print(System.out);
      }

      ((HandshakeMessage)var17).write(this.output);
      this.output.doHashes();
      this.output.flush();
      Object var20;
      switch($SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange()[this.keyExchange.ordinal()]) {
      case 2:
      case 3:
         var20 = ((RSAClientKeyExchange)var17).preMaster;
         break;
      case 4:
      case 5:
      default:
         throw new IOException("Internal error: unknown key exchange " + this.keyExchange);
      case 6:
      case 7:
      case 8:
         var20 = this.dh.getAgreedSecret(this.serverDH);
         break;
      case 9:
      case 10:
         var20 = this.ecdh.getAgreedSecret(this.sigServerKey);
         break;
      case 11:
      case 12:
      case 13:
         var20 = this.ecdh.getAgreedSecret(this.ephemeralServerKey);
         break;
      case 14:
         if (this.protocolVersion.minor == 0) {
            var20 = this.ecdh.getAgreedSecret(this.ephemeralServerKey);
         } else {
            if (this.protocolVersion.minor != 1) {
               throw new RuntimeException("unsupported protocol version");
            }

            this.sm2.setPeerPublicKey(this.encServerKey);
            var20 = this.sm2.getAgreedSecret(this.ephemeralServerKey, this.encIdLocal, this.encIdRemote);
         }
         break;
      case 15:
         var20 = ((ECCClientKeyExchange)var17).preMaster;
         break;
      case 16:
      case 17:
         byte[] var23 = ((KerberosClientKeyExchange)var17).getUnencryptedPreMasterSecret();
         var20 = new SecretKeySpec(var23, "TlsPremasterSecret");
      }

      this.calculateKeys((SecretKey)var20, (ProtocolVersion)null);
      if (var2 == null) {
         if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
            this.handshakeHash.setCertificateVerifyAlg((String)null);
         }
      } else {
         HandshakeMessage.CertificateVerify var25;
         try {
            SignatureAndHashAlgorithm var27 = null;
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
               var27 = SignatureAndHashAlgorithm.getPreferableAlgorithm(this.peerSupportedSignAlgs, var2.getAlgorithm());
               if (var27 == null) {
                  throw new SSLHandshakeException("No supported signature algorithm");
               }

               var28 = SignatureAndHashAlgorithm.getHashAlgorithmName(var27);
               if (var28 == null || var28.length() == 0) {
                  throw new SSLHandshakeException("No supported hash algorithm");
               }

               this.handshakeHash.setCertificateVerifyAlg(var28);
            }

            var25 = new HandshakeMessage.CertificateVerify(this.protocolVersion, this.handshakeHash, var2, this.session.getMasterSecret(), this.sslContext.getSecureRandom(), var27, this.clientPublicKey, this.idLocal);
         } catch (GeneralSecurityException var16) {
            this.fatalSE((byte)40, "Error signing certificate verify", var16);
            var25 = null;
         }

         if (debug != null && Debug.isOn("handshake")) {
            var25.print(System.out);
         }

         var25.write(this.output);
         this.output.doHashes();
      }

      this.sendChangeCipherAndFinish(false);
   }

   private void serverFinished(HandshakeMessage.Finished var1) throws IOException {
      if (debug != null && Debug.isOn("handshake")) {
         var1.print(System.out);
      }

      boolean var2 = var1.verify(this.handshakeHash, 2, this.session.getMasterSecret());
      if (!var2) {
         this.fatalSE((byte)47, "server 'finished' message doesn't verify");
      }

      if (this.secureRenegotiation) {
         this.serverVerifyData = var1.getVerifyData();
      }

      if (this.resumingSession) {
         this.input.digestNow();
         this.sendChangeCipherAndFinish(true);
      }

      this.session.setLastAccessedTime(System.currentTimeMillis());
      if (!this.resumingSession) {
         if (this.session.isRejoinable()) {
            ((SSLSessionContextImpl)this.sslContext.engineGetClientSessionContext()).put(this.session);
            if (debug != null && Debug.isOn("session")) {
               System.out.println("%% Cached client session: " + this.session);
            }
         } else if (debug != null && Debug.isOn("session")) {
            System.out.println("%% Didn't cache non-resumable client session: " + this.session);
         }
      }

   }

   private void sendChangeCipherAndFinish(boolean var1) throws IOException {
      HandshakeMessage.Finished var2 = new HandshakeMessage.Finished(this.protocolVersion, this.handshakeHash, 1, this.session.getMasterSecret(), this.cipherSuite);
      this.sendChangeCipherSpec(var2, var1);
      if (this.secureRenegotiation) {
         this.clientVerifyData = var2.getVerifyData();
      }

      this.state = 19;
   }

   HandshakeMessage getKickstartMessage() throws SSLException {
      SessionId var1 = SSLSessionImpl.nullSession.getSessionId();
      CipherSuiteList var2 = this.getActiveCipherSuites();
      this.maxProtocolVersion = this.protocolVersion;
      this.session = ((SSLSessionContextImpl)this.sslContext.engineGetClientSessionContext()).get(this.getHostSE(), this.getPortSE());
      if (debug != null && Debug.isOn("session")) {
         if (this.session != null) {
            System.out.println("%% Client cached " + this.session + (this.session.isRejoinable() ? "" : " (not rejoinable)"));
         } else {
            System.out.println("%% No cached client session");
         }
      }

      if (this.session != null && !this.session.isRejoinable()) {
         this.session = null;
      }

      if (this.session != null) {
         CipherSuite var3 = this.session.getSuite();
         ProtocolVersion var4 = this.session.getProtocolVersion();
         if (!this.isNegotiable(var3)) {
            if (debug != null && Debug.isOn("session")) {
               System.out.println("%% can't resume, unavailable cipher");
            }

            this.session = null;
         }

         if (this.session != null && !this.isNegotiable(var4)) {
            if (debug != null && Debug.isOn("session")) {
               System.out.println("%% can't resume, protocol disabled");
            }

            this.session = null;
         }

         if (this.session != null) {
            if (debug != null && (Debug.isOn("handshake") || Debug.isOn("session"))) {
               System.out.println("%% Try resuming " + this.session + " from port " + this.getLocalPortSE());
            }

            var1 = this.session.getSessionId();
            this.maxProtocolVersion = var4;
            this.setVersion(var4);
         }

         if (!this.enableNewSession) {
            if (this.session == null) {
               throw new SSLHandshakeException("Can't reuse existing SSL client session");
            }

            ArrayList var5 = new ArrayList(2);
            var5.add(var3);
            if (!this.secureRenegotiation && var2.contains(CipherSuite.C_SCSV)) {
               var5.add(CipherSuite.C_SCSV);
            }

            var2 = new CipherSuiteList(var5);
         }
      }

      if (this.session == null && !this.enableNewSession) {
         throw new SSLHandshakeException("No existing session to resume");
      } else {
         CipherSuite var8;
         Iterator var10;
         if (this.secureRenegotiation && var2.contains(CipherSuite.C_SCSV)) {
            ArrayList var6 = new ArrayList(var2.size() - 1);
            var10 = var2.collection().iterator();

            while(var10.hasNext()) {
               var8 = (CipherSuite)var10.next();
               if (var8 != CipherSuite.C_SCSV) {
                  var6.add(var8);
               }
            }

            var2 = new CipherSuiteList(var6);
         }

         boolean var7 = false;
         var10 = var2.collection().iterator();

         while(var10.hasNext()) {
            var8 = (CipherSuite)var10.next();
            if (this.isNegotiable(var8)) {
               var7 = true;
               break;
            }
         }

         if (!var7) {
            throw new SSLHandshakeException("No negotiable cipher suite");
         } else {
            HandshakeMessage.ClientHello var9 = new HandshakeMessage.ClientHello(this.sslContext.getSecureRandom(), this.maxProtocolVersion, var1, var2);
            if (this.maxProtocolVersion.v >= ProtocolVersion.TLS12.v) {
               Collection var11 = this.getLocalSupportedSignAlgs();
               if (var11.isEmpty()) {
                  throw new SSLHandshakeException("No supported signature algorithm");
               }

               var9.addSignatureAlgorithmsExtension(var11);
            }

            if (enableSNIExtension) {
               String var12 = this.getRawHostnameSE();
               if (var12 != null && var12.indexOf(46) > 0 && !IPAddressUtil.isIPv4LiteralAddress(var12) && !IPAddressUtil.isIPv6LiteralAddress(var12)) {
                  var9.addServerNameIndicationExtension(var12);
               }
            }

            this.clnt_random = var9.clnt_random;
            if (this.secureRenegotiation || !var2.contains(CipherSuite.C_SCSV)) {
               var9.addRenegotiationInfoExtension(this.clientVerifyData);
            }

            return var9;
         }
      }
   }

   void handshakeAlert(byte var1) throws SSLProtocolException {
      String var2 = Alerts.alertDescription(var1);
      if (debug != null && Debug.isOn("handshake")) {
         System.out.println("SSL - handshake alert: " + var2);
      }

      throw new SSLProtocolException("handshake alert:  " + var2);
   }

   private void serverCertificate(HandshakeMessage.CertificateMsg var1) throws IOException {
      if (debug != null && Debug.isOn("handshake")) {
         var1.print(System.out);
      }

      X509Certificate[] var2 = var1.getCertificateChain();
      if (var2.length == 0) {
         this.fatalSE((byte)42, "empty certificate chain");
      }

      X509TrustManager var3 = this.sslContext.getX509TrustManager();

      try {
         String var4;
         if (this.keyExchange == CipherSuite.KeyExchange.K_RSA_EXPORT && !this.serverKeyExchangeReceived) {
            var4 = CipherSuite.KeyExchange.K_RSA.name;
         } else {
            var4 = this.keyExchange.name;
         }

         if (!(var3 instanceof X509ExtendedTrustManager)) {
            throw new CertificateException("Improper X509TrustManager implementation");
         }

         if (this.conn == null) {
            ((X509ExtendedTrustManager)var3).checkServerTrusted((X509Certificate[])var2.clone(), var4, this.engine);
         }
      } catch (CertificateException var5) {
         this.fatalSE((byte)46, var5);
      }

      this.session.setPeerCertificates(var2);
   }

   // $FF: synthetic method
   static int[] $SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange() {
      int[] var10000 = $SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange;
      if ($SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange != null) {
         return var10000;
      } else {
         int[] var0 = new int[CipherSuite.KeyExchange.values().length];

         try {
            var0[CipherSuite.KeyExchange.K_DHE_DSS.ordinal()] = 6;
         } catch (NoSuchFieldError var18) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_DHE_RSA.ordinal()] = 7;
         } catch (NoSuchFieldError var17) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_DH_ANON.ordinal()] = 8;
         } catch (NoSuchFieldError var16) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_DH_DSS.ordinal()] = 5;
         } catch (NoSuchFieldError var15) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_DH_RSA.ordinal()] = 4;
         } catch (NoSuchFieldError var14) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_ECC.ordinal()] = 15;
         } catch (NoSuchFieldError var13) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_ECDHE_ECDSA.ordinal()] = 11;
         } catch (NoSuchFieldError var12) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_ECDHE_RSA.ordinal()] = 12;
         } catch (NoSuchFieldError var11) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_ECDH_ANON.ordinal()] = 13;
         } catch (NoSuchFieldError var10) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_ECDH_ECDSA.ordinal()] = 9;
         } catch (NoSuchFieldError var9) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_ECDH_RSA.ordinal()] = 10;
         } catch (NoSuchFieldError var8) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_KRB5.ordinal()] = 16;
         } catch (NoSuchFieldError var7) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_KRB5_EXPORT.ordinal()] = 17;
         } catch (NoSuchFieldError var6) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_NULL.ordinal()] = 1;
         } catch (NoSuchFieldError var5) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_RSA.ordinal()] = 2;
         } catch (NoSuchFieldError var4) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_RSA_EXPORT.ordinal()] = 3;
         } catch (NoSuchFieldError var3) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_SCSV.ordinal()] = 18;
         } catch (NoSuchFieldError var2) {
            ;
         }

         try {
            var0[CipherSuite.KeyExchange.K_SM2_SM2.ordinal()] = 14;
         } catch (NoSuchFieldError var1) {
            ;
         }

         $SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange = var0;
         return var0;
      }
   }
}
