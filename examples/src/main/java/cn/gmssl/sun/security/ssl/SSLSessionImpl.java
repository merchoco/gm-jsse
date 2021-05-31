package cn.gmssl.sun.security.ssl;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import javax.crypto.SecretKey;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLPermission;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.CertificateException;

final class SSLSessionImpl extends ExtendedSSLSession {
   static final SSLSessionImpl nullSession = new SSLSessionImpl();
   private static final byte compression_null = 0;
   private final ProtocolVersion protocolVersion;
   private final SessionId sessionId;
   private X509Certificate[] peerCerts;
   private byte compressionMethod;
   private CipherSuite cipherSuite;
   private SecretKey masterSecret;
   private final long creationTime;
   private long lastUsedTime;
   private final String host;
   private final int port;
   private SSLSessionContextImpl context;
   private int sessionCount;
   private boolean invalidated;
   private X509Certificate[] localCerts;
   private PrivateKey localPrivateKey;
   private String[] localSupportedSignAlgs;
   private String[] peerSupportedSignAlgs;
   private Principal peerPrincipal;
   private Principal localPrincipal;
   private static volatile int counter = 0;
   private static boolean defaultRejoinable = true;
   private static final Debug debug = Debug.getInstance("ssl");
   private Hashtable<SecureKey, Object> table;
   private boolean acceptLargeFragments;

   private SSLSessionImpl() {
      this(ProtocolVersion.NONE, CipherSuite.C_NULL, (Collection)null, (SessionId)(new SessionId(false, (SecureRandom)null)), (String)null, -1);
   }

   SSLSessionImpl(ProtocolVersion var1, CipherSuite var2, Collection<SignatureAndHashAlgorithm> var3, SecureRandom var4, String var5, int var6) {
      this(var1, var2, var3, new SessionId(defaultRejoinable, var4), var5, var6);
   }

   SSLSessionImpl(ProtocolVersion var1, CipherSuite var2, Collection<SignatureAndHashAlgorithm> var3, SessionId var4, String var5, int var6) {
      this.creationTime = System.currentTimeMillis();
      this.lastUsedTime = 0L;
      this.table = new Hashtable();
      this.acceptLargeFragments = Debug.getBooleanProperty("jsse.SSLEngine.acceptLargeFragments", false);
      this.protocolVersion = var1;
      this.sessionId = var4;
      this.peerCerts = null;
      this.compressionMethod = 0;
      this.cipherSuite = var2;
      this.masterSecret = null;
      this.host = var5;
      this.port = var6;
      this.sessionCount = ++counter;
      this.localSupportedSignAlgs = SignatureAndHashAlgorithm.getAlgorithmNames(var3);
      if (debug != null && Debug.isOn("session")) {
         System.out.println("%% Initialized:  " + this);
      }

   }

   void setMasterSecret(SecretKey var1) {
      if (this.masterSecret == null) {
         this.masterSecret = var1;
      } else {
         throw new RuntimeException("setMasterSecret() error");
      }
   }

   SecretKey getMasterSecret() {
      return this.masterSecret;
   }

   void setPeerCertificates(X509Certificate[] var1) {
      if (this.peerCerts == null) {
         this.peerCerts = var1;
      }

   }

   void setLocalCertificates(X509Certificate[] var1) {
      this.localCerts = var1;
   }

   void setLocalPrivateKey(PrivateKey var1) {
      this.localPrivateKey = var1;
   }

   void setPeerSupportedSignatureAlgorithms(Collection<SignatureAndHashAlgorithm> var1) {
      this.peerSupportedSignAlgs = SignatureAndHashAlgorithm.getAlgorithmNames(var1);
   }

   void setPeerPrincipal(Principal var1) {
      if (this.peerPrincipal == null) {
         this.peerPrincipal = var1;
      }

   }

   void setLocalPrincipal(Principal var1) {
      this.localPrincipal = var1;
   }

   boolean isRejoinable() {
      return this.sessionId != null && this.sessionId.length() != 0 && !this.invalidated && this.isLocalAuthenticationValid();
   }

   public synchronized boolean isValid() {
      return this.isRejoinable();
   }

   boolean isLocalAuthenticationValid() {
      if (this.localPrivateKey != null) {
         try {
            this.localPrivateKey.getAlgorithm();
         } catch (Exception var2) {
            this.invalidate();
            return false;
         }
      }

      return true;
   }

   public byte[] getId() {
      return this.sessionId.getId();
   }

   public SSLSessionContext getSessionContext() {
      SecurityManager var1;
      if ((var1 = System.getSecurityManager()) != null) {
         var1.checkPermission(new SSLPermission("getSSLSessionContext"));
      }

      return this.context;
   }

   SessionId getSessionId() {
      return this.sessionId;
   }

   CipherSuite getSuite() {
      return this.cipherSuite;
   }

   void setSuite(CipherSuite var1) {
      this.cipherSuite = var1;
      if (debug != null && Debug.isOn("session")) {
         System.out.println("%% Negotiating:  " + this);
      }

   }

   public String getCipherSuite() {
      return this.getSuite().name;
   }

   ProtocolVersion getProtocolVersion() {
      return this.protocolVersion;
   }

   public String getProtocol() {
      return this.getProtocolVersion().name;
   }

   byte getCompression() {
      return this.compressionMethod;
   }

   public int hashCode() {
      return this.sessionId.hashCode();
   }

   public boolean equals(Object var1) {
      if (var1 == this) {
         return true;
      } else if (var1 instanceof SSLSessionImpl) {
         SSLSessionImpl var2 = (SSLSessionImpl)var1;
         return this.sessionId != null && this.sessionId.equals(var2.getSessionId());
      } else {
         return false;
      }
   }

   public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
      if (this.cipherSuite.keyExchange != CipherSuite.KeyExchange.K_KRB5 && this.cipherSuite.keyExchange != CipherSuite.KeyExchange.K_KRB5_EXPORT) {
         if (this.peerCerts == null) {
            throw new SSLPeerUnverifiedException("peer not authenticated");
         } else {
            return (Certificate[])this.peerCerts.clone();
         }
      } else {
         throw new SSLPeerUnverifiedException("no certificates expected for Kerberos cipher suites");
      }
   }

   public Certificate[] getLocalCertificates() {
      return this.localCerts == null ? null : (Certificate[])this.localCerts.clone();
   }

   public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
      if (this.cipherSuite.keyExchange != CipherSuite.KeyExchange.K_KRB5 && this.cipherSuite.keyExchange != CipherSuite.KeyExchange.K_KRB5_EXPORT) {
         if (this.peerCerts == null) {
            throw new SSLPeerUnverifiedException("peer not authenticated");
         } else {
            javax.security.cert.X509Certificate[] var1 = new javax.security.cert.X509Certificate[this.peerCerts.length];

            for(int var2 = 0; var2 < this.peerCerts.length; ++var2) {
               Object var3 = null;

               try {
                  byte[] var7 = this.peerCerts[var2].getEncoded();
                  var1[var2] = javax.security.cert.X509Certificate.getInstance(var7);
               } catch (CertificateEncodingException var5) {
                  throw new SSLPeerUnverifiedException(var5.getMessage());
               } catch (CertificateException var6) {
                  throw new SSLPeerUnverifiedException(var6.getMessage());
               }
            }

            return var1;
         }
      } else {
         throw new SSLPeerUnverifiedException("no certificates expected for Kerberos cipher suites");
      }
   }

   public X509Certificate[] getCertificateChain() throws SSLPeerUnverifiedException {
      if (this.cipherSuite.keyExchange != CipherSuite.KeyExchange.K_KRB5 && this.cipherSuite.keyExchange != CipherSuite.KeyExchange.K_KRB5_EXPORT) {
         if (this.peerCerts != null) {
            return (X509Certificate[])this.peerCerts.clone();
         } else {
            throw new SSLPeerUnverifiedException("peer not authenticated");
         }
      } else {
         throw new SSLPeerUnverifiedException("no certificates expected for Kerberos cipher suites");
      }
   }

   public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
      if (this.cipherSuite.keyExchange != CipherSuite.KeyExchange.K_KRB5 && this.cipherSuite.keyExchange != CipherSuite.KeyExchange.K_KRB5_EXPORT) {
         if (this.peerCerts == null) {
            throw new SSLPeerUnverifiedException("peer not authenticated");
         } else {
            return this.peerCerts[0].getSubjectX500Principal();
         }
      } else if (this.peerPrincipal == null) {
         throw new SSLPeerUnverifiedException("peer not authenticated");
      } else {
         return this.peerPrincipal;
      }
   }

   public Principal getLocalPrincipal() {
      if (this.cipherSuite.keyExchange != CipherSuite.KeyExchange.K_KRB5 && this.cipherSuite.keyExchange != CipherSuite.KeyExchange.K_KRB5_EXPORT) {
         return this.localCerts == null ? null : this.localCerts[0].getSubjectX500Principal();
      } else {
         return this.localPrincipal == null ? null : this.localPrincipal;
      }
   }

   public long getCreationTime() {
      return this.creationTime;
   }

   public long getLastAccessedTime() {
      return this.lastUsedTime != 0L ? this.lastUsedTime : this.creationTime;
   }

   void setLastAccessedTime(long var1) {
      this.lastUsedTime = var1;
   }

   public InetAddress getPeerAddress() {
      try {
         return InetAddress.getByName(this.host);
      } catch (UnknownHostException var2) {
         return null;
      }
   }

   public String getPeerHost() {
      return this.host;
   }

   public int getPeerPort() {
      return this.port;
   }

   void setContext(SSLSessionContextImpl var1) {
      if (this.context == null) {
         this.context = var1;
      }

   }

   public synchronized void invalidate() {
      if (this != nullSession) {
         this.invalidated = true;
         if (debug != null && Debug.isOn("session")) {
            System.out.println("%% Invalidated:  " + this);
         }

         if (this.context != null) {
            this.context.remove(this.sessionId);
            this.context = null;
         }

      }
   }

   public void putValue(String var1, Object var2) {
      if (var1 != null && var2 != null) {
         SecureKey var3 = new SecureKey(var1);
         Object var4 = this.table.put(var3, var2);
         SSLSessionBindingEvent var5;
         if (var4 instanceof SSLSessionBindingListener) {
            var5 = new SSLSessionBindingEvent(this, var1);
            ((SSLSessionBindingListener)var4).valueUnbound(var5);
         }

         if (var2 instanceof SSLSessionBindingListener) {
            var5 = new SSLSessionBindingEvent(this, var1);
            ((SSLSessionBindingListener)var2).valueBound(var5);
         }

      } else {
         throw new IllegalArgumentException("arguments can not be null");
      }
   }

   public Object getValue(String var1) {
      if (var1 == null) {
         throw new IllegalArgumentException("argument can not be null");
      } else {
         SecureKey var2 = new SecureKey(var1);
         return this.table.get(var2);
      }
   }

   public void removeValue(String var1) {
      if (var1 == null) {
         throw new IllegalArgumentException("argument can not be null");
      } else {
         SecureKey var2 = new SecureKey(var1);
         Object var3 = this.table.remove(var2);
         if (var3 instanceof SSLSessionBindingListener) {
            SSLSessionBindingEvent var4 = new SSLSessionBindingEvent(this, var1);
            ((SSLSessionBindingListener)var3).valueUnbound(var4);
         }

      }
   }

   public String[] getValueNames() {
      Vector var2 = new Vector();
      Object var4 = SecureKey.getCurrentSecurityContext();
      Enumeration var1 = this.table.keys();

      while(var1.hasMoreElements()) {
         SecureKey var3 = (SecureKey)var1.nextElement();
         if (var4.equals(var3.getSecurityContext())) {
            var2.addElement(var3.getAppKey());
         }
      }

      String[] var5 = new String[var2.size()];
      var2.copyInto(var5);
      return var5;
   }

   protected synchronized void expandBufferSizes() {
      this.acceptLargeFragments = true;
   }

   public synchronized int getPacketBufferSize() {
      return this.acceptLargeFragments ? '舙' : 16921;
   }

   public synchronized int getApplicationBufferSize() {
      return this.getPacketBufferSize() - 5;
   }

   public String[] getLocalSupportedSignatureAlgorithms() {
      return this.localSupportedSignAlgs != null ? (String[])this.localSupportedSignAlgs.clone() : new String[0];
   }

   public String[] getPeerSupportedSignatureAlgorithms() {
      return this.peerSupportedSignAlgs != null ? (String[])this.peerSupportedSignAlgs.clone() : new String[0];
   }

   public String toString() {
      return "[Session-" + this.sessionCount + ", " + this.getCipherSuite() + "]";
   }

   public void finalize() {
      String[] var1 = this.getValueNames();

      for(int var2 = 0; var2 < var1.length; ++var2) {
         this.removeValue(var1[var2]);
      }

   }
}
