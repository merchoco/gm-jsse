package cn.gmssl.sun.security.ssl;

import cn.gmssl.com.jsse.SM2CertUtil;
import cn.gmssl.crypto.impl.sm2.SM2Util;
import cn.gmssl.jsse.provider.GMConf;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.Set;
import java.util.Vector;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.Subject;

final class ServerHandshaker extends Handshaker {
   private byte doClientAuth;
   private X509Certificate[] certs;
   private PrivateKey privateKey;
   private X509Certificate[] encCerts;
   private PrivateKey encPrivateKey;
   private SecretKey[] kerberosKeys;
   private boolean needClientVerify = false;
   private PrivateKey tempPrivateKey;
   private PublicKey tempPublicKey;
   private DHCrypt dh;
   private ECDHCrypt ecdh;
   private SM2Crypt sm2;
   private byte[] idLocal = null;
   private byte[] idRemote = null;
   private byte[] encIdLocal = null;
   private byte[] encIdRemote = null;
   private ProtocolVersion clientRequestedVersion;
   private SupportedEllipticCurvesExtension supportedCurves;
   SignatureAndHashAlgorithm preferableSignatureAlgorithm;
   public boolean single = System.getProperty("record.single_msg") != null;
   // $FF: synthetic field
   private static int[] $SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange;

   ServerHandshaker(SSLSocketImpl var1, SSLContextImpl var2, ProtocolList var3, byte var4, ProtocolVersion var5, boolean var6, boolean var7, byte[] var8, byte[] var9) {
      super(var1, var2, var3, var4 != 0, false, var5, var6, var7, var8, var9);
      this.doClientAuth = var4;
   }

   ServerHandshaker(SSLEngineImpl var1, SSLContextImpl var2, ProtocolList var3, byte var4, ProtocolVersion var5, boolean var6, boolean var7, byte[] var8, byte[] var9) {
      super(var1, var2, var3, var4 != 0, false, var5, var6, var7, var8, var9);
      this.doClientAuth = var4;
   }

   void setClientAuth(byte var1) {
      this.doClientAuth = var1;
   }

   void processMessage(byte var1, int var2) throws IOException {
      if (this.state > var1 && this.state != 16 && var1 != 15) {
         throw new SSLProtocolException("Handshake message sequence violation, state = " + this.state + ", type = " + var1);
      } else {
         switch(var1) {
         case 1:
            HandshakeMessage.ClientHello var3 = new HandshakeMessage.ClientHello(this.input, var2);
            this.clientHello(var3);
            break;
         case 11:
            if (this.doClientAuth == 0) {
               this.fatalSE((byte)10, "client sent unsolicited cert chain");
            }

            this.clientCertificate(new HandshakeMessage.CertificateMsg(this.input));
            break;
         case 15:
            this.clientCertificateVerify(new HandshakeMessage.CertificateVerify(this.input, this.localSupportedSignAlgs, this.protocolVersion));
            break;
         case 16:
            SecretKey var4;
            switch($SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange()[this.keyExchange.ordinal()]) {
            case 2:
            case 3:
               RSAClientKeyExchange var5 = new RSAClientKeyExchange(this.protocolVersion, this.clientRequestedVersion, this.sslContext.getSecureRandom(), this.input, var2, this.privateKey);
               var4 = this.clientKeyExchange(var5);
               break;
            case 4:
            case 5:
            default:
               throw new SSLProtocolException("Unrecognized key exchange: " + this.keyExchange);
            case 6:
            case 7:
            case 8:
               var4 = this.clientKeyExchange(new DHClientKeyExchange(this.input));
               break;
            case 9:
            case 10:
            case 11:
            case 12:
            case 13:
               var4 = this.clientKeyExchange(new ECDHClientKeyExchange(this.input));
               break;
            case 14:
               var4 = this.clientKeyExchange(new SM2ClientKeyExchange(this.input));
               break;
            case 15:
               ECCClientKeyExchange var6 = new ECCClientKeyExchange(this.protocolVersion, this.clientRequestedVersion, this.sslContext.getSecureRandom(), this.input, var2, this.encPrivateKey, this.sb);
               var4 = this.clientKeyExchange(var6);
               break;
            case 16:
            case 17:
               var4 = this.clientKeyExchange(new KerberosClientKeyExchange(this.protocolVersion, this.clientRequestedVersion, this.sslContext.getSecureRandom(), this.input, this.kerberosKeys));
            }

            this.calculateKeys(var4, this.clientRequestedVersion);
            break;
         case 20:
            this.clientFinished(new HandshakeMessage.Finished(this.protocolVersion, this.input, this.cipherSuite));
            break;
         default:
            throw new SSLProtocolException("Illegal server handshake msg, " + var1);
         }

         if (this.state < var1 && var1 != 15) {
            this.state = var1;
         }

      }
   }

   private void clientHello(HandshakeMessage.ClientHello var1) throws IOException {
      if (debug != null && Debug.isOn("handshake")) {
         var1.print(System.out);
      }

      boolean var2 = false;
      CipherSuiteList var3 = var1.getCipherSuites();
      if (var3.contains(CipherSuite.C_SCSV)) {
         var2 = true;
         if (this.isInitialHandshake) {
            this.secureRenegotiation = true;
         } else if (this.secureRenegotiation) {
            this.fatalSE((byte)40, "The SCSV is present in a secure renegotiation");
         } else {
            this.fatalSE((byte)40, "The SCSV is present in a insecure renegotiation");
         }
      }

      RenegotiationInfoExtension var4 = (RenegotiationInfoExtension)var1.extensions.get(ExtensionType.EXT_RENEGOTIATION_INFO);
      if (var4 != null) {
         var2 = true;
         if (this.isInitialHandshake) {
            if (!var4.isEmpty()) {
               this.fatalSE((byte)40, "The renegotiation_info field is not empty");
            }

            this.secureRenegotiation = true;
         } else {
            if (!this.secureRenegotiation) {
               this.fatalSE((byte)40, "The renegotiation_info is present in a insecure renegotiation");
            }

            if (!Arrays.equals(this.clientVerifyData, var4.getRenegotiatedConnection())) {
               this.fatalSE((byte)40, "Incorrect verify data in ClientHello renegotiation_info message");
            }
         }
      } else if (!this.isInitialHandshake && this.secureRenegotiation) {
         this.fatalSE((byte)40, "Inconsistent secure renegotiation indication");
      }

      if (!var2 || !this.secureRenegotiation) {
         if (this.isInitialHandshake) {
            if (!allowLegacyHelloMessages) {
               this.fatalSE((byte)40, "Failed to negotiate the use of secure renegotiation");
            }

            if (debug != null && Debug.isOn("handshake")) {
               System.out.println("Warning: No renegotiation indication in ClientHello, allow legacy ClientHello");
            }
         } else if (!allowUnsafeRenegotiation) {
            if (this.activeProtocolVersion.v >= ProtocolVersion.TLS10.v) {
               this.warningSE((byte)100);
               this.invalidated = true;
               if (this.input.available() > 0) {
                  this.fatalSE((byte)10, "ClientHello followed by an unexpected  handshake message");
               }

               return;
            }

            this.fatalSE((byte)40, "Renegotiation is not allowed");
         } else if (debug != null && Debug.isOn("handshake")) {
            System.out.println("Warning: continue with insecure renegotiation");
         }
      }

      this.input.digestNow();
      HandshakeMessage.ServerHello var5 = new HandshakeMessage.ServerHello();
      this.clientRequestedVersion = var1.protocolVersion;
      ProtocolVersion var6 = this.selectProtocolVersion(this.clientRequestedVersion);
      if (var6 == null || var6.v == ProtocolVersion.SSL20Hello.v) {
         this.fatalSE((byte)40, "Client requested protocol " + this.clientRequestedVersion + " not enabled or not supported");
      }

      this.handshakeHash.protocolDetermined(var6);
      this.setVersion(var6);
      var5.protocolVersion = this.protocolVersion;
      this.clnt_random = var1.clnt_random;
      this.svr_random = new RandomCookie(this.sslContext.getSecureRandom());
      var5.svr_random = this.svr_random;
      this.session = null;
      SSLSessionImpl var7;
      Set var11;
      if (var1.sessionId.length() != 0) {
         var7 = ((SSLSessionContextImpl)this.sslContext.engineGetServerSessionContext()).get(var1.sessionId.getId());
         if (var7 != null) {
            this.resumingSession = var7.isRejoinable();
            if (this.resumingSession) {
               ProtocolVersion var8 = var7.getProtocolVersion();
               if (var8 != this.protocolVersion) {
                  this.resumingSession = false;
               }
            }

            if (this.resumingSession && this.doClientAuth == 2) {
               try {
                  var7.getPeerPrincipal();
               } catch (SSLPeerUnverifiedException var17) {
                  this.resumingSession = false;
               }
            }

            CipherSuite var21;
            if (this.resumingSession) {
               var21 = var7.getSuite();
               if (var21.keyExchange == CipherSuite.KeyExchange.K_KRB5 || var21.keyExchange == CipherSuite.KeyExchange.K_KRB5_EXPORT) {
                  Principal var9 = var7.getLocalPrincipal();
                  Subject var10 = null;

                  try {
                     var10 = (Subject)AccessController.doPrivileged(new PrivilegedExceptionAction<Subject>() {
                        public Subject run() throws Exception {
                           return Krb5Helper.getServerSubject(ServerHandshaker.this.getAccSE());
                        }
                     });
                  } catch (PrivilegedActionException var18) {
                     var10 = null;
                     if (debug != null && Debug.isOn("session")) {
                        System.out.println("Attempt to obtain subject failed!");
                     }
                  }

                  if (var10 != null) {
                     var11 = var10.getPrincipals(Principal.class);
                     if (!var11.contains(var9)) {
                        this.resumingSession = false;
                        if (debug != null && Debug.isOn("session")) {
                           System.out.println("Subject identity is not the same");
                        }
                     } else if (debug != null && Debug.isOn("session")) {
                        System.out.println("Subject identity is same");
                     }
                  } else {
                     this.resumingSession = false;
                     if (debug != null && Debug.isOn("session")) {
                        System.out.println("Kerberos credentials are not present in the current Subject; check if  javax.security.auth.useSubjectAsCreds system property has been set to false");
                     }
                  }
               }
            }

            if (this.resumingSession) {
               var21 = var7.getSuite();
               if (this.isNegotiable(var21) && var1.getCipherSuites().contains(var21)) {
                  this.setCipherSuite(var21);
               } else {
                  this.resumingSession = false;
               }
            }

            if (this.resumingSession) {
               this.session = var7;
               if (debug != null && (Debug.isOn("handshake") || Debug.isOn("session"))) {
                  System.out.println("%% Resuming " + this.session);
               }
            }
         }
      }

      if (this.session == null) {
         if (!this.enableNewSession) {
            throw new SSLException("Client did not resume a session");
         }

         this.supportedCurves = (SupportedEllipticCurvesExtension)var1.extensions.get(ExtensionType.EXT_ELLIPTIC_CURVES);
         if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
            SignatureAlgorithmsExtension var19 = (SignatureAlgorithmsExtension)var1.extensions.get(ExtensionType.EXT_SIGNATURE_ALGORITHMS);
            if (var19 != null) {
               Collection var23 = var19.getSignAlgorithms();
               if (var23 == null || var23.isEmpty()) {
                  throw new SSLHandshakeException("No peer supported signature algorithms");
               }

               Collection var24 = SignatureAndHashAlgorithm.getSupportedAlgorithms(var23);
               if (var24.isEmpty()) {
                  throw new SSLHandshakeException("No supported signature and hash algorithm in common");
               }

               this.setPeerSupportedSignAlgs(var24);
            }
         }

         this.session = new SSLSessionImpl(this.protocolVersion, CipherSuite.C_NULL, this.getLocalSupportedSignAlgs(), this.sslContext.getSecureRandom(), this.getHostAddressSE(), this.getPortSE());
         if (this.protocolVersion.v >= ProtocolVersion.TLS12.v && this.peerSupportedSignAlgs != null) {
            this.session.setPeerSupportedSignatureAlgorithms(this.peerSupportedSignAlgs);
         }

         this.setHandshakeSessionSE(this.session);
         this.chooseCipherSuite(var1);
         this.session.setSuite(this.cipherSuite);
         this.session.setLocalPrivateKey(this.privateKey);
      } else {
         this.setHandshakeSessionSE(this.session);
      }

      if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
         if (this.resumingSession) {
            this.handshakeHash.setCertificateVerifyAlg((String)null);
         }

         this.handshakeHash.setFinishedAlg(this.cipherSuite.prfAlg.getPRFHashAlg());
      }

      var5.cipherSuite = this.cipherSuite;
      var5.sessionId = this.session.getSessionId();
      var5.compression_method = this.session.getCompression();
      if (this.secureRenegotiation) {
         RenegotiationInfoExtension var20 = new RenegotiationInfoExtension(this.clientVerifyData, this.serverVerifyData);
         var5.extensions.add(var20);
      }

      if (debug != null && Debug.isOn("handshake")) {
         var5.print(System.out);
         System.out.println("Cipher suite:  " + this.session.getSuite());
      }

      var5.write(this.output);
      this.flushRecord();
      if (this.resumingSession) {
         this.calculateConnectionKeys(this.session.getMasterSecret());
         this.sendChangeCipherAndFinish(false);
      } else {
         if (this.keyExchange != CipherSuite.KeyExchange.K_KRB5 && this.keyExchange != CipherSuite.KeyExchange.K_KRB5_EXPORT) {
            if (this.keyExchange != CipherSuite.KeyExchange.K_DH_ANON && this.keyExchange != CipherSuite.KeyExchange.K_ECDH_ANON) {
               if (this.certs == null) {
                  throw new RuntimeException("no certificates");
               }

               var7 = null;
               HandshakeMessage.CertificateMsg var22;
               if (this.protocolVersion.major == 1 && this.protocolVersion.minor == 1) {
                  X509Certificate[] var25 = new X509Certificate[this.certs.length + 1];
                  var25[0] = this.certs[0];
                  var25[1] = this.encCerts[0];

                  for(int var28 = 0; var28 < this.certs.length - 1; ++var28) {
                     var25[2 + var28] = this.certs[1 + var28];
                  }

                  var22 = new HandshakeMessage.CertificateMsg(var25);
                  this.session.setLocalCertificates(var25);
               } else {
                  var22 = new HandshakeMessage.CertificateMsg(this.certs);
                  this.session.setLocalCertificates(this.certs);
               }

               if (debug != null && Debug.isOn("handshake")) {
                  var22.print(System.out);
               }

               var22.write(this.output);
               this.flushRecord();
            } else if (this.certs != null) {
               throw new RuntimeException("anonymous keyexchange with certs");
            }
         }

         Object var26 = null;
         switch($SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange()[this.keyExchange.ordinal()]) {
         case 2:
         case 16:
         case 17:
            var26 = null;
            break;
         case 3:
            if (JsseJce.getRSAKeyLength(this.certs[0].getPublicKey()) > 512) {
               try {
                  var26 = new HandshakeMessage.RSA_ServerKeyExchange(this.tempPublicKey, this.privateKey, this.clnt_random, this.svr_random, this.sslContext.getSecureRandom());
                  this.privateKey = this.tempPrivateKey;
               } catch (GeneralSecurityException var15) {
                  throwSSLException("Error generating RSA server key exchange", var15);
                  var26 = null;
               }
            } else {
               var26 = null;
            }
            break;
         case 4:
         case 5:
         default:
            throw new RuntimeException("internal error: " + this.keyExchange);
         case 6:
         case 7:
            try {
               var26 = new HandshakeMessage.DH_ServerKeyExchange(this.dh, this.privateKey, this.clnt_random.random_bytes, this.svr_random.random_bytes, this.sslContext.getSecureRandom(), this.preferableSignatureAlgorithm, this.protocolVersion);
            } catch (GeneralSecurityException var14) {
               throwSSLException("Error generating DH server key exchange", var14);
               var26 = null;
            }
            break;
         case 8:
            var26 = new HandshakeMessage.DH_ServerKeyExchange(this.dh, this.protocolVersion);
            break;
         case 9:
         case 10:
            var26 = null;
            break;
         case 11:
         case 12:
         case 13:
            try {
               var26 = new HandshakeMessage.ECDH_ServerKeyExchange(this.ecdh, this.privateKey, this.clnt_random.random_bytes, this.svr_random.random_bytes, this.sslContext.getSecureRandom(), this.preferableSignatureAlgorithm, this.protocolVersion);
            } catch (GeneralSecurityException var13) {
               throwSSLException("Error generating ECDH server key exchange", var13);
               var26 = null;
            }
            break;
         case 14:
            if (this.protocolVersion.major != 1) {
               throw new RuntimeException("gb tls protocol version major must be 1");
            }

            try {
               if (this.protocolVersion.minor == 0) {
                  var26 = new HandshakeMessage.SM2_ServerKeyExchange(this.ecdh, this.privateKey, this.clnt_random.random_bytes, this.svr_random.random_bytes, this.sslContext.getSecureRandom(), this.preferableSignatureAlgorithm, this.protocolVersion);
               } else {
                  if (this.protocolVersion.minor != 1) {
                     throw new RuntimeException("unsupported protocol version");
                  }

                  var26 = new HandshakeMessage.SM2_ServerKeyExchange(this.sm2, this.privateKey, this.clnt_random.random_bytes, this.svr_random.random_bytes, this.sslContext.getSecureRandom(), this.preferableSignatureAlgorithm, this.protocolVersion, this.idLocal, this.certs[0].getPublicKey());
               }
            } catch (GeneralSecurityException var12) {
               throwSSLException("Error generating ECDH server key exchange", var12);
               var26 = null;
            }
            break;
         case 15:
            String var27 = System.getProperty("ecc_server_key_exchange");
            if (var27 != null) {
               try {
                  var26 = new ECCServerKeyExchange(this.privateKey, this.certs[0].getPublicKey(), this.clnt_random, this.svr_random, this.encCerts[0], this.sslContext.getSecureRandom());
               } catch (Exception var16) {
                  ;
               }
            }
         }

         if (var26 != null) {
            if (debug != null && Debug.isOn("handshake")) {
               ((HandshakeMessage.ServerKeyExchange)var26).print(System.out);
            }

            ((HandshakeMessage.ServerKeyExchange)var26).write(this.output);
            this.flushRecord();
         }

         if (this.doClientAuth != 0 && this.keyExchange != CipherSuite.KeyExchange.K_DH_ANON && this.keyExchange != CipherSuite.KeyExchange.K_ECDH_ANON && this.keyExchange != CipherSuite.KeyExchange.K_KRB5 && this.keyExchange != CipherSuite.KeyExchange.K_KRB5_EXPORT) {
            Collection var32 = null;
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
               var32 = this.getLocalSupportedSignAlgs();
               if (var32.isEmpty()) {
                  throw new SSLHandshakeException("No supported signature algorithm");
               }

               var11 = SignatureAndHashAlgorithm.getHashAlgorithmNames(var32);
               if (var11.isEmpty()) {
                  throw new SSLHandshakeException("No supported signature algorithm");
               }

               this.handshakeHash.restrictCertificateVerifyAlgs(var11);
            }

            X509Certificate[] var30 = this.sslContext.getX509TrustManager().getAcceptedIssuers();
            HandshakeMessage.CertificateRequest var29 = new HandshakeMessage.CertificateRequest(var30, this.keyExchange, var32, this.protocolVersion);
            if (debug != null && Debug.isOn("handshake")) {
               var29.print(System.out);
            }

            var29.write(this.output);
            this.flushRecord();
         } else if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
            this.handshakeHash.setCertificateVerifyAlg((String)null);
         }

         HandshakeMessage.ServerHelloDone var31 = new HandshakeMessage.ServerHelloDone();
         if (debug != null && Debug.isOn("handshake")) {
            var31.print(System.out);
         }

         var31.write(this.output);
         this.flushRecord();
         this.output.flush();
      }
   }

   private void chooseCipherSuite(HandshakeMessage.ClientHello var1) throws IOException {
      if (GMConf.debug) {
         System.out.println("chooseCipherSuite...");
      }

      int var2 = 0;
      Collection var3 = var1.getCipherSuites().collection();
      Iterator var4 = var3.iterator();
      Vector var5 = new Vector();

      CipherSuite var6;
      while(var4.hasNext()) {
         var6 = (CipherSuite)var4.next();
         var5.addElement(var6);
      }

      Collections.sort(var5, new ServerHandshaker.SuiteComparator());
      Iterator var7 = var5.iterator();

      while(true) {
         while(var7.hasNext()) {
            var6 = (CipherSuite)var7.next();
            if (GMConf.debug) {
               System.out.println("chooseCipherSuite suite" + var2++ + "=" + var6);
            }

            if (!this.isNegotiable(var6)) {
               if (GMConf.debug) {
                  System.out.println("chooseCipherSuite suite" + var2 + "=" + var6 + " continue1");
               }
            } else {
               if (GMConf.debug) {
                  System.out.println("chooseCipherSuite suite2");
               }

               if (this.doClientAuth == 2 && (var6.keyExchange == CipherSuite.KeyExchange.K_DH_ANON || var6.keyExchange == CipherSuite.KeyExchange.K_ECDH_ANON)) {
                  if (GMConf.debug) {
                     System.out.println("chooseCipherSuite suite" + var2 + "=" + var6 + " continue2");
                  }
               } else {
                  if (GMConf.debug) {
                     System.out.println("chooseCipherSuite suite3");
                  }

                  if (this.trySetCipherSuite(var6)) {
                     return;
                  }

                  if (GMConf.debug) {
                     System.out.println("suite" + var2 + "=" + var6 + " continue3");
                  }
               }
            }
         }

         this.fatalSE((byte)40, "no cipher suites in common");
         return;
      }
   }

   boolean trySetCipherSuite(CipherSuite var1) {
      if (GMConf.debug) {
         System.out.println("trySetCipherSuite=" + var1 + " protocolVersion=" + this.protocolVersion);
      }

      if (this.resumingSession) {
         return true;
      } else if (!var1.isNegotiable()) {
         if (GMConf.debug) {
            System.out.println("trySetCipherSuite isNegotiable false");
         }

         return false;
      } else if (this.protocolVersion.v >= var1.obsoleted && var1.name.indexOf("SM4") == -1) {
         if (GMConf.debug) {
            System.out.println("trySetCipherSuite obsoleted false " + this.protocolVersion.v + " " + var1.obsoleted);
         }

         return false;
      } else if (this.protocolVersion.v < var1.supported) {
         if (GMConf.debug) {
            System.out.println("trySetCipherSuite supported false " + this.protocolVersion.v + " " + var1.supported);
         }

         return false;
      } else {
         CipherSuite.KeyExchange var2 = var1.keyExchange;
         this.privateKey = null;
         this.certs = null;
         this.dh = null;
         this.tempPrivateKey = null;
         this.tempPublicKey = null;
         Object var3 = null;
         if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
            if (this.peerSupportedSignAlgs != null) {
               var3 = this.peerSupportedSignAlgs;
            } else {
               SignatureAndHashAlgorithm var4 = null;
               switch($SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange()[var2.ordinal()]) {
               case 2:
               case 4:
               case 7:
               case 10:
               case 12:
                  var4 = SignatureAndHashAlgorithm.valueOf(SignatureAndHashAlgorithm.HashAlgorithm.SHA1.value, SignatureAndHashAlgorithm.SignatureAlgorithm.RSA.value, 0);
               case 3:
               case 8:
               default:
                  break;
               case 5:
               case 6:
                  var4 = SignatureAndHashAlgorithm.valueOf(SignatureAndHashAlgorithm.HashAlgorithm.SHA1.value, SignatureAndHashAlgorithm.SignatureAlgorithm.DSA.value, 0);
                  break;
               case 9:
               case 11:
                  var4 = SignatureAndHashAlgorithm.valueOf(SignatureAndHashAlgorithm.HashAlgorithm.SHA1.value, SignatureAndHashAlgorithm.SignatureAlgorithm.ECDSA.value, 0);
               }

               if (var4 == null) {
                  var3 = Collections.emptySet();
               } else {
                  var3 = new ArrayList(1);
                  ((Collection)var3).add(var4);
               }

               this.session.setPeerSupportedSignatureAlgorithms((Collection)var3);
            }
         }

         if (GMConf.debug) {
            System.out.println("trySetCipherSuite keyExchange=" + var2);
         }

         switch($SWITCH_TABLE$cn$gmssl$sun$security$ssl$CipherSuite$KeyExchange()[var2.ordinal()]) {
         case 2:
            if (!this.setupPrivateKeyAndChain("RSA")) {
               if (GMConf.debug) {
                  System.out.println("trySetCipherSuite RSA false");
               }

               return false;
            }
            break;
         case 3:
            if (!this.setupPrivateKeyAndChain("RSA")) {
               return false;
            }

            try {
               if (JsseJce.getRSAKeyLength(this.certs[0].getPublicKey()) > 512 && !this.setupEphemeralRSAKeys(var1.exportable)) {
                  return false;
               }
               break;
            } catch (RuntimeException var5) {
               return false;
            }
         case 4:
         case 5:
         default:
            throw new RuntimeException("Unrecognized cipherSuite: " + var1);
         case 6:
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
               this.preferableSignatureAlgorithm = SignatureAndHashAlgorithm.getPreferableAlgorithm((Collection)var3, "DSA");
               if (this.preferableSignatureAlgorithm == null) {
                  return false;
               }
            }

            if (!this.setupPrivateKeyAndChain("DSA")) {
               return false;
            }

            this.setupEphemeralDHKeys(var1.exportable);
            break;
         case 7:
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
               this.preferableSignatureAlgorithm = SignatureAndHashAlgorithm.getPreferableAlgorithm((Collection)var3, "RSA");
               if (this.preferableSignatureAlgorithm == null) {
                  return false;
               }
            }

            if (!this.setupPrivateKeyAndChain("RSA")) {
               return false;
            }

            this.setupEphemeralDHKeys(var1.exportable);
            break;
         case 8:
            this.setupEphemeralDHKeys(var1.exportable);
            break;
         case 9:
            if (!this.setupPrivateKeyAndChain("EC_EC")) {
               return false;
            }

            this.setupStaticECDHKeys();
            break;
         case 10:
            if (!this.setupPrivateKeyAndChain("EC_RSA")) {
               return false;
            }

            this.setupStaticECDHKeys();
            break;
         case 11:
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
               this.preferableSignatureAlgorithm = SignatureAndHashAlgorithm.getPreferableAlgorithm((Collection)var3, "ECDSA");
               if (this.preferableSignatureAlgorithm == null) {
                  return false;
               }
            }

            if (!this.setupPrivateKeyAndChain("EC_EC")) {
               return false;
            }

            if (!this.setupEphemeralECDHKeys()) {
               return false;
            }
            break;
         case 12:
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
               this.preferableSignatureAlgorithm = SignatureAndHashAlgorithm.getPreferableAlgorithm((Collection)var3, "RSA");
               if (this.preferableSignatureAlgorithm == null) {
                  return false;
               }
            }

            if (!this.setupPrivateKeyAndChain("RSA")) {
               return false;
            }

            if (!this.setupEphemeralECDHKeys()) {
               return false;
            }
            break;
         case 13:
            if (!this.setupEphemeralECDHKeys()) {
               return false;
            }
            break;
         case 14:
            if (!this.setupPrivateKeyAndChain("EC_EC")) {
               return false;
            }

            if (this.protocolVersion.minor == 0) {
               if (!this.setupEphemeralECDHKeys()) {
                  return false;
               }
            } else if (!this.setupEphemeralSM2Keys()) {
               return false;
            }
            break;
         case 15:
            if (!this.setupPrivateKeyAndChain("EC_EC")) {
               return false;
            }
            break;
         case 16:
         case 17:
            if (!this.setupKerberosKeys()) {
               return false;
            }
         }

         this.setCipherSuite(var1);
         if (this.protocolVersion.v >= ProtocolVersion.TLS12.v && this.peerSupportedSignAlgs == null) {
            this.setPeerSupportedSignAlgs((Collection)var3);
         }

         return true;
      }
   }

   private boolean setupEphemeralRSAKeys(boolean var1) {
      KeyPair var2 = this.sslContext.getEphemeralKeyManager().getRSAKeyPair(var1, this.sslContext.getSecureRandom());
      if (var2 == null) {
         return false;
      } else {
         this.tempPublicKey = var2.getPublic();
         this.tempPrivateKey = var2.getPrivate();
         return true;
      }
   }

   private void setupEphemeralDHKeys(boolean var1) {
      this.dh = new DHCrypt(var1 ? 512 : 768, this.sslContext.getSecureRandom());
   }

   private boolean setupEphemeralECDHKeys() {
      int var1 = -1;
      if (this.protocolVersion.major == 1) {
         var1 = 23;
      } else if (this.supportedCurves != null) {
         int[] var5;
         int var4 = (var5 = this.supportedCurves.curveIds()).length;

         for(int var3 = 0; var3 < var4; ++var3) {
            int var2 = var5[var3];
            if (SupportedEllipticCurvesExtension.isSupported(var2)) {
               var1 = var2;
               break;
            }
         }

         if (var1 < 0) {
            return false;
         }
      } else {
         var1 = SupportedEllipticCurvesExtension.DEFAULT.curveIds()[0];
      }

      String var6 = SupportedEllipticCurvesExtension.getCurveOid(var1);
      this.ecdh = new ECDHCrypt(var6, this.sslContext.getSecureRandom());
      return true;
   }

   private void setupStaticECDHKeys() {
      this.ecdh = new ECDHCrypt(this.privateKey, this.certs[0].getPublicKey());
   }

   private boolean setupEphemeralSM2Keys() {
      this.idLocal = SM2Util.getId(this.certs[0], this.protocolVersion.minor);
      this.encIdLocal = SM2Util.getId(this.encCerts[0], this.protocolVersion.minor);
      this.sm2 = new SM2Crypt(this.encCerts[0].getPublicKey(), this.encPrivateKey, this.sslContext.getSecureRandom(), true);
      return true;
   }

   private boolean setupPrivateKeyAndChain(String var1) {
      if (GMConf.debug) {
         System.out.println("setupPrivateKeyAndChain algorithm=" + var1);
      }

      X509ExtendedKeyManager var2 = this.sslContext.getX509KeyManager();
      String var3;
      if (this.conn != null) {
         var3 = var2.chooseServerAlias(var1, (Principal[])null, this.conn);
      } else {
         var3 = var2.chooseEngineServerAlias(var1, (Principal[])null, this.engine);
      }

      if (var3 == null) {
         return false;
      } else {
         int var4 = var3.indexOf(58);
         if (GMConf.debug) {
            System.out.println("setupPrivateKeyAndChain aliasIndex=" + var4);
         }

         if (var4 == -1) {
            PrivateKey var5 = var2.getPrivateKey(var3);
            if (GMConf.debug) {
               System.out.println("setupPrivateKeyAndChain tempPrivateKey=" + var5);
            }

            if (var5 == null) {
               return false;
            }

            X509Certificate[] var6 = var2.getCertificateChain(var3);
            if (GMConf.debug) {
               System.out.println("setupPrivateKeyAndChain tempCerts=" + var6);
            }

            if (var6 == null || var6.length == 0) {
               return false;
            }

            String var7 = var1.split("_")[0];
            PublicKey var8 = var6[0].getPublicKey();
            if (!var5.getAlgorithm().equals(var7) || !var8.getAlgorithm().equals(var7)) {
               return false;
            }

            if (this.protocolVersion.major != 1 && var7.equals("EC")) {
               if (!(var8 instanceof ECPublicKey)) {
                  return false;
               }

               ECParameterSpec var9 = ((ECPublicKey)var8).getParams();
               int var10 = SupportedEllipticCurvesExtension.getCurveIndex(var9);
               if (!SupportedEllipticCurvesExtension.isSupported(var10)) {
                  return false;
               }

               if (this.supportedCurves != null && !this.supportedCurves.contains(var10)) {
                  return false;
               }
            }

            this.privateKey = var5;
            this.certs = var6;
         } else {
            String var14 = var3.substring(0, var4);
            String var15 = var3.substring(var4 + 1);
            if (GMConf.debug) {
               System.out.println("setupPrivateKeyAndChain alias1=" + var14);
            }

            if (GMConf.debug) {
               System.out.println("setupPrivateKeyAndChain alias2=" + var15);
            }

            PrivateKey var16 = var2.getPrivateKey(var14);
            if (GMConf.debug) {
               System.out.println("setupPrivateKeyAndChain tempPrivateKey1=" + var16);
            }

            if (var16 == null) {
               return false;
            }

            PrivateKey var17 = var2.getPrivateKey(var15);
            if (GMConf.debug) {
               System.out.println("setupPrivateKeyAndChain tempPrivateKey2=" + var17);
            }

            if (var17 == null) {
               return false;
            }

            X509Certificate[] var18 = var2.getCertificateChain(var14);
            if (GMConf.debug) {
               System.out.println("setupPrivateKeyAndChain tempCerts1=" + var18);
            }

            if (var18 == null || var18.length == 0) {
               return false;
            }

            X509Certificate[] var19 = var2.getCertificateChain(var15);
            if (GMConf.debug) {
               System.out.println("setupPrivateKeyAndChain tempCerts2=" + var19);
            }

            if (var19 == null || var19.length == 0) {
               return false;
            }

            if (GMConf.debug) {
               System.out.println("setupPrivateKeyAndChain encryptCert?");
            }

            if (SM2CertUtil.encryptCert(var18[0]) && SM2CertUtil.signCert(var19[0])) {
               if (GMConf.debug) {
                  System.out.println("setupPrivateKeyAndChain encryptCert!");
               }

               this.encPrivateKey = var16;
               this.encCerts = var18;
               this.privateKey = var17;
               this.certs = var19;
               if (GMConf.debug) {
                  System.out.println("setupPrivateKeyAndChain encryptCert...");
               }
            } else if (SM2CertUtil.encryptCert(var19[0]) && SM2CertUtil.signCert(var18[0])) {
               this.encPrivateKey = var17;
               this.encCerts = var19;
               this.privateKey = var16;
               this.certs = var18;
               if (GMConf.debug) {
                  System.out.println("setupPrivateKeyAndChain signCert!");
               }
            } else {
               System.err.println("SM2 double keypair usage error!");
            }

            try {
               Class var11 = Class.forName("cn.gmssl.jsse.provider.GMTrustasia");
               Method var12 = var11.getMethod("init", X509Certificate.class);
               var12.invoke((Object)null, this.certs[0]);
            } catch (Throwable var13) {
               ;
            }
         }

         return true;
      }
   }

   private boolean setupKerberosKeys() {
      if (this.kerberosKeys != null) {
         return true;
      } else {
         try {
            final AccessControlContext var1 = this.getAccSE();
            this.kerberosKeys = (SecretKey[])AccessController.doPrivileged(new PrivilegedExceptionAction<SecretKey[]>() {
               public SecretKey[] run() throws Exception {
                  return Krb5Helper.getServerKeys(var1);
               }
            });
            if (this.kerberosKeys != null && this.kerberosKeys.length > 0) {
               if (debug != null && Debug.isOn("handshake")) {
                  SecretKey[] var5 = this.kerberosKeys;
                  int var4 = this.kerberosKeys.length;

                  for(int var3 = 0; var3 < var4; ++var3) {
                     SecretKey var2 = var5[var3];
                     System.out.println("Using Kerberos key: " + var2);
                  }
               }

               String var8 = Krb5Helper.getServerPrincipalName(this.kerberosKeys[0]);
               SecurityManager var9 = System.getSecurityManager();

               try {
                  if (var9 != null) {
                     var9.checkPermission(Krb5Helper.getServicePermission(var8, "accept"), var1);
                  }
               } catch (SecurityException var6) {
                  this.kerberosKeys = null;
                  if (debug != null && Debug.isOn("handshake")) {
                     System.out.println("Permission to access Kerberos secret key denied");
                  }

                  return false;
               }
            }

            return this.kerberosKeys != null;
         } catch (PrivilegedActionException var7) {
            if (debug != null && Debug.isOn("handshake")) {
               System.out.println("Attempt to obtain Kerberos key failed: " + var7.toString());
            }

            return false;
         }
      }
   }

   private SecretKey clientKeyExchange(KerberosClientKeyExchange var1) throws IOException {
      if (debug != null && Debug.isOn("handshake")) {
         var1.print(System.out);
      }

      this.session.setPeerPrincipal(var1.getPeerPrincipal());
      this.session.setLocalPrincipal(var1.getLocalPrincipal());
      byte[] var2 = var1.getUnencryptedPreMasterSecret();
      return new SecretKeySpec(var2, "TlsPremasterSecret");
   }

   private SecretKey clientKeyExchange(DHClientKeyExchange var1) throws IOException {
      if (debug != null && Debug.isOn("handshake")) {
         var1.print(System.out);
      }

      return this.dh.getAgreedSecret(var1.getClientPublicKey());
   }

   private SecretKey clientKeyExchange(ECDHClientKeyExchange var1) throws IOException {
      if (debug != null && Debug.isOn("handshake")) {
         var1.print(System.out);
      }

      return this.ecdh.getAgreedSecret(var1.getEncodedPoint());
   }

   private SecretKey clientKeyExchange(SM2ClientKeyExchange var1) throws IOException {
      if (debug != null && Debug.isOn("handshake")) {
         var1.print(System.out);
      }

      this.sm2.setPeerPublicKey(this.session.getPeerCertificateChain()[1].getPublicKey());
      this.sm2.sb = super.sb;
      return this.sm2.getAgreedSecret(var1.getEncodedPoint(), this.encIdLocal, this.encIdRemote);
   }

   private void clientCertificateVerify(HandshakeMessage.CertificateVerify var1) throws IOException {
      if (debug != null && Debug.isOn("handshake")) {
         var1.print(System.out);
      }

      if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
         SignatureAndHashAlgorithm var2 = var1.getPreferableSignatureAlgorithm();
         if (var2 == null) {
            throw new SSLHandshakeException("Illegal CertificateVerify message");
         }

         String var3 = SignatureAndHashAlgorithm.getHashAlgorithmName(var2);
         if (var3 == null || var3.length() == 0) {
            throw new SSLHandshakeException("No supported hash algorithm");
         }

         this.handshakeHash.setCertificateVerifyAlg(var3);
      }

      try {
         PublicKey var5 = this.session.getPeerCertificates()[0].getPublicKey();
         boolean var6 = var1.verify(this.protocolVersion, this.handshakeHash, var5, this.session.getMasterSecret(), this.cipherSuite.name, this.idRemote);
         if (!var6) {
            this.fatalSE((byte)42, "certificate verify message signature error");
         }
      } catch (GeneralSecurityException var4) {
         this.fatalSE((byte)42, "certificate verify format error", var4);
      }

      this.needClientVerify = false;
   }

   private void clientFinished(HandshakeMessage.Finished var1) throws IOException {
      if (debug != null && Debug.isOn("handshake")) {
         var1.print(System.out);
      }

      if (this.doClientAuth == 2) {
         this.session.getPeerPrincipal();
      }

      if (this.needClientVerify) {
         this.fatalSE((byte)40, "client did not send certificate verify message");
      }

      boolean var2 = var1.verify(this.handshakeHash, 1, this.session.getMasterSecret());
      if (!var2) {
         this.fatalSE((byte)40, "client 'finished' message doesn't verify");
      }

      if (this.secureRenegotiation) {
         this.clientVerifyData = var1.getVerifyData();
      }

      if (!this.resumingSession) {
         this.input.digestNow();
         this.sendChangeCipherAndFinish(true);
      }

      this.session.setLastAccessedTime(System.currentTimeMillis());
      if (!this.resumingSession && this.session.isRejoinable()) {
         ((SSLSessionContextImpl)this.sslContext.engineGetServerSessionContext()).put(this.session);
         if (debug != null && Debug.isOn("session")) {
            System.out.println("%% Cached server session: " + this.session);
         }
      } else if (!this.resumingSession && debug != null && Debug.isOn("session")) {
         System.out.println("%% Didn't cache non-resumable server session: " + this.session);
      }

   }

   private void sendChangeCipherAndFinish(boolean var1) throws IOException {
      this.output.flush();
      HandshakeMessage.Finished var2 = new HandshakeMessage.Finished(this.protocolVersion, this.handshakeHash, 2, this.session.getMasterSecret(), this.cipherSuite);
      this.sendChangeCipherSpec(var2, var1);
      if (this.secureRenegotiation) {
         this.serverVerifyData = var2.getVerifyData();
      }

      if (var1) {
         this.state = 20;
      }

   }

   HandshakeMessage getKickstartMessage() {
      return new HandshakeMessage.HelloRequest();
   }

   void handshakeAlert(byte var1) throws SSLProtocolException {
      String var2 = Alerts.alertDescription(var1);
      if (debug != null && Debug.isOn("handshake")) {
         System.out.println("SSL -- handshake alert:  " + var2);
      }

      if (var1 != 41 || this.doClientAuth != 1) {
         throw new SSLProtocolException("handshake alert: " + var2);
      }
   }

   private SecretKey clientKeyExchange(RSAClientKeyExchange var1) throws IOException {
      if (debug != null && Debug.isOn("handshake")) {
         var1.print(System.out);
      }

      return var1.preMaster;
   }

   private SecretKey clientKeyExchange(ECCClientKeyExchange var1) throws IOException {
      if (debug != null && Debug.isOn("handshake")) {
         var1.print(System.out);
      }

      return var1.preMaster;
   }

   private void clientCertificate(HandshakeMessage.CertificateMsg var1) throws IOException {
      if (debug != null && Debug.isOn("handshake")) {
         var1.print(System.out);
      }

      X509Certificate[] var2 = var1.getCertificateChain();
      if (var2.length == 0) {
         if (this.doClientAuth == 1) {
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
               this.handshakeHash.setCertificateVerifyAlg((String)null);
            }

            return;
         }

         this.fatalSE((byte)42, "null cert chain");
      }

      X509TrustManager var3 = this.sslContext.getX509TrustManager();

      try {
         PublicKey var4 = var2[0].getPublicKey();
         String var5 = var4.getAlgorithm();
         String var6;
         if (var5.equals("RSA")) {
            var6 = "RSA";
         } else if (var5.equals("DSA")) {
            var6 = "DSA";
         } else if (var5.equals("EC")) {
            var6 = "EC";
         } else {
            var6 = "UNKNOWN";
         }

         if (!(var3 instanceof X509ExtendedTrustManager)) {
            throw new CertificateException("Improper X509TrustManager implementation");
         }

         if (this.conn == null) {
            ((X509ExtendedTrustManager)var3).checkClientTrusted((X509Certificate[])var2.clone(), var6, this.engine);
         }
      } catch (CertificateException var7) {
         this.fatalSE((byte)46, var7);
      }

      this.needClientVerify = true;
      this.session.setPeerCertificates(var2);
      this.idRemote = SM2Util.getId(var2[0], this.protocolVersion.minor);
      if (this.protocolVersion.major == 1) {
         this.encIdRemote = SM2Util.getId(var2[1], this.protocolVersion.minor);
      }

   }

   private void flushRecord() throws IOException {
      if (this.single) {
         this.output.flush();
      }

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

   static class SuiteComparator implements Comparator {
      public int compare(Object var1, Object var2) {
         CipherSuite var3 = (CipherSuite)var1;
         CipherSuite var4 = (CipherSuite)var2;
         if (var3.name.indexOf("SM4") != -1 && var4.name.indexOf("SM4") == -1) {
            return -1;
         } else {
            return var3.name.indexOf("SM4") == -1 && var4.name.indexOf("SM4") != -1 ? 1 : var3.name.compareTo(var4.name);
         }
      }
   }
}
