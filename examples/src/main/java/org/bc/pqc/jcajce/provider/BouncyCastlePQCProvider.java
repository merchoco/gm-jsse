package org.bc.pqc.jcajce.provider;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.pkcs.PrivateKeyInfo;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.config.ProviderConfiguration;
import org.bc.jcajce.provider.util.AlgorithmProvider;
import org.bc.jcajce.provider.util.AsymmetricKeyInfoConverter;

public class BouncyCastlePQCProvider extends Provider implements ConfigurableProvider {
   private static String info = "BouncyCastle Post-Quantum Security Provider v1.48";
   public static String PROVIDER_NAME = "BCPQC";
   public static final ProviderConfiguration CONFIGURATION = null;
   private static final Map keyInfoConverters = new HashMap();
   private static final String ALGORITHM_PACKAGE = "org.bc.pqc.jcajce.provider.";
   private static final String[] ALGORITHMS = new String[]{"Rainbow", "McEliece"};

   public BouncyCastlePQCProvider() {
      super(PROVIDER_NAME, 1.48D, info);
      AccessController.doPrivileged(new PrivilegedAction() {
         public Object run() {
            BouncyCastlePQCProvider.this.setup();
            return null;
         }
      });
   }

   private void setup() {
      this.loadAlgorithms("org.bc.pqc.jcajce.provider.", ALGORITHMS);
   }

   private void loadAlgorithms(String var1, String[] var2) {
      for(int var3 = 0; var3 != var2.length; ++var3) {
         Class var4 = null;

         try {
            ClassLoader var5 = this.getClass().getClassLoader();
            if (var5 != null) {
               var4 = var5.loadClass(var1 + var2[var3] + "$Mappings");
            } else {
               var4 = Class.forName(var1 + var2[var3] + "$Mappings");
            }
         } catch (ClassNotFoundException var7) {
            ;
         }

         if (var4 != null) {
            try {
               ((AlgorithmProvider)var4.newInstance()).configure(this);
            } catch (Exception var6) {
               throw new InternalError("cannot create instance of " + var1 + var2[var3] + "$Mappings : " + var6);
            }
         }
      }

   }

   public void setParameter(String var1, Object var2) {
      synchronized(CONFIGURATION){}
   }

   public boolean hasAlgorithm(String var1, String var2) {
      return this.containsKey(var1 + "." + var2) || this.containsKey("Alg.Alias." + var1 + "." + var2);
   }

   public void addAlgorithm(String var1, String var2) {
      if (this.containsKey(var1)) {
         throw new IllegalStateException("duplicate provider key (" + var1 + ") found");
      } else {
         this.put(var1, var2);
      }
   }

   public void addKeyInfoConverter(ASN1ObjectIdentifier var1, AsymmetricKeyInfoConverter var2) {
      keyInfoConverters.put(var1, var2);
   }

   public static PublicKey getPublicKey(SubjectPublicKeyInfo var0) throws IOException {
      AsymmetricKeyInfoConverter var1 = (AsymmetricKeyInfoConverter)keyInfoConverters.get(var0.getAlgorithm().getAlgorithm());
      return var1 == null ? null : var1.generatePublic(var0);
   }

   public static PrivateKey getPrivateKey(PrivateKeyInfo var0) throws IOException {
      AsymmetricKeyInfoConverter var1 = (AsymmetricKeyInfoConverter)keyInfoConverters.get(var0.getPrivateKeyAlgorithm().getAlgorithm());
      return var1 == null ? null : var1.generatePrivate(var0);
   }
}
