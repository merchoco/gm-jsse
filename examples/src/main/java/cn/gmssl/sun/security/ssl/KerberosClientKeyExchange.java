package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.io.PrintStream;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import javax.crypto.SecretKey;

public class KerberosClientKeyExchange extends HandshakeMessage {
   private static final String IMPL_CLASS = "sun.security.ssl.krb5.KerberosClientKeyExchangeImpl";
   private static final Class<?> implClass = (Class)AccessController.doPrivileged(new PrivilegedAction<Class<?>>() {
      public Class<?> run() {
         try {
            return Class.forName("sun.security.ssl.krb5.KerberosClientKeyExchangeImpl", true, (ClassLoader)null);
         } catch (ClassNotFoundException var2) {
            return null;
         }
      }
   });
   private final KerberosClientKeyExchange impl = this.createImpl();

   private KerberosClientKeyExchange createImpl() {
      if (this.getClass() == KerberosClientKeyExchange.class) {
         try {
            return (KerberosClientKeyExchange)implClass.newInstance();
         } catch (InstantiationException var2) {
            throw new AssertionError(var2);
         } catch (IllegalAccessException var3) {
            throw new AssertionError(var3);
         }
      } else {
         return null;
      }
   }

   public KerberosClientKeyExchange() {
   }

   public KerberosClientKeyExchange(String var1, boolean var2, AccessControlContext var3, ProtocolVersion var4, SecureRandom var5) throws IOException {
      if (this.impl != null) {
         this.init(var1, var2, var3, var4, var5);
      } else {
         throw new IllegalStateException("Kerberos is unavailable");
      }
   }

   public KerberosClientKeyExchange(ProtocolVersion var1, ProtocolVersion var2, SecureRandom var3, HandshakeInStream var4, SecretKey[] var5) throws IOException {
      if (this.impl != null) {
         this.init(var1, var2, var3, var4, var5);
      } else {
         throw new IllegalStateException("Kerberos is unavailable");
      }
   }

   int messageType() {
      return 16;
   }

   public int messageLength() {
      return this.impl.messageLength();
   }

   public void send(HandshakeOutStream var1) throws IOException {
      this.impl.send(var1);
   }

   public void print(PrintStream var1) throws IOException {
      this.impl.print(var1);
   }

   public void init(String var1, boolean var2, AccessControlContext var3, ProtocolVersion var4, SecureRandom var5) throws IOException {
      if (this.impl != null) {
         this.impl.init(var1, var2, var3, var4, var5);
      }

   }

   public void init(ProtocolVersion var1, ProtocolVersion var2, SecureRandom var3, HandshakeInStream var4, SecretKey[] var5) throws IOException {
      if (this.impl != null) {
         this.impl.init(var1, var2, var3, var4, var5);
      }

   }

   public byte[] getUnencryptedPreMasterSecret() {
      return this.impl.getUnencryptedPreMasterSecret();
   }

   public Principal getPeerPrincipal() {
      return this.impl.getPeerPrincipal();
   }

   public Principal getLocalPrincipal() {
      return this.impl.getLocalPrincipal();
   }
}
