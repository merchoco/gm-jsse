package org.bc.jcajce.provider.config;

import javax.crypto.spec.DHParameterSpec;
import org.bc.jce.spec.ECParameterSpec;

public interface ProviderConfiguration {
   ECParameterSpec getEcImplicitlyCa();

   DHParameterSpec getDHDefaultParameters(int var1);
}
