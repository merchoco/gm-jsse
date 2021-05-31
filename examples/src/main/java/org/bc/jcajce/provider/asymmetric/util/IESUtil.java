package org.bc.jcajce.provider.asymmetric.util;

import org.bc.crypto.engines.IESEngine;
import org.bc.jce.spec.IESParameterSpec;

public class IESUtil {
   public static IESParameterSpec guessParameterSpec(IESEngine var0) {
      if (var0.getCipher() == null) {
         return new IESParameterSpec((byte[])null, (byte[])null, 128);
      } else if (!var0.getCipher().getUnderlyingCipher().getAlgorithmName().equals("DES") && !var0.getCipher().getUnderlyingCipher().getAlgorithmName().equals("RC2") && !var0.getCipher().getUnderlyingCipher().getAlgorithmName().equals("RC5-32") && !var0.getCipher().getUnderlyingCipher().getAlgorithmName().equals("RC5-64")) {
         if (var0.getCipher().getUnderlyingCipher().getAlgorithmName().equals("SKIPJACK")) {
            return new IESParameterSpec((byte[])null, (byte[])null, 80, 80);
         } else {
            return var0.getCipher().getUnderlyingCipher().getAlgorithmName().equals("GOST28147") ? new IESParameterSpec((byte[])null, (byte[])null, 256, 256) : new IESParameterSpec((byte[])null, (byte[])null, 128, 128);
         }
      } else {
         return new IESParameterSpec((byte[])null, (byte[])null, 64, 64);
      }
   }
}
