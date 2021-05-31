package org.bc.jcajce.provider.config;

import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.jcajce.provider.util.AsymmetricKeyInfoConverter;

public interface ConfigurableProvider {
   String THREAD_LOCAL_EC_IMPLICITLY_CA = "threadLocalEcImplicitlyCa";
   String EC_IMPLICITLY_CA = "ecImplicitlyCa";
   String THREAD_LOCAL_DH_DEFAULT_PARAMS = "threadLocalDhDefaultParams";
   String DH_DEFAULT_PARAMS = "DhDefaultParams";

   void setParameter(String var1, Object var2);

   void addAlgorithm(String var1, String var2);

   boolean hasAlgorithm(String var1, String var2);

   void addKeyInfoConverter(ASN1ObjectIdentifier var1, AsymmetricKeyInfoConverter var2);
}
