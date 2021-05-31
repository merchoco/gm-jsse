package cn.gmssl.sun.security.ssl;

import cn.gmssl.jsse.provider.GMConf;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class CipherSuite implements Comparable {
   static final int SUPPORTED_SUITES_PRIORITY = 1;
   static final int DEFAULT_SUITES_PRIORITY = 300;
   static final boolean DYNAMIC_AVAILABILITY = true;
   private static final boolean ALLOW_ECC = Debug.getBooleanProperty("com.sun.net.ssl.enableECC", true);
   private static final Map<Integer, CipherSuite> idMap = new HashMap();
   private static final Map<String, CipherSuite> nameMap = new HashMap();
   final String name;
   final int id;
   final int priority;
   final CipherSuite.KeyExchange keyExchange;
   final CipherSuite.BulkCipher cipher;
   final CipherSuite.MacAlg macAlg;
   final CipherSuite.PRF prfAlg;
   final boolean exportable;
   final boolean allowed;
   final int obsoleted;
   final int supported;
   static final CipherSuite.BulkCipher B_NULL = new CipherSuite.BulkCipher("NULL", 0, 0, 0, true);
   static final CipherSuite.BulkCipher B_RC4_40 = new CipherSuite.BulkCipher("RC4", 5, 16, 0, true);
   static final CipherSuite.BulkCipher B_RC2_40 = new CipherSuite.BulkCipher("RC2", 5, 16, 8, false);
   static final CipherSuite.BulkCipher B_DES_40 = new CipherSuite.BulkCipher("DES/CBC/NoPadding", 5, 8, 8, true);
   static final CipherSuite.BulkCipher B_RC4_128 = new CipherSuite.BulkCipher("RC4", 16, 0, true);
   static final CipherSuite.BulkCipher B_DES = new CipherSuite.BulkCipher("DES/CBC/NoPadding", 8, 8, true);
   static final CipherSuite.BulkCipher B_3DES = new CipherSuite.BulkCipher("DESede/CBC/NoPadding", 24, 8, true);
   static final CipherSuite.BulkCipher B_IDEA = new CipherSuite.BulkCipher("IDEA", 16, 8, false);
   static final CipherSuite.BulkCipher B_AES_128 = new CipherSuite.BulkCipher("AES/CBC/NoPadding", 16, 16, true);
   static final CipherSuite.BulkCipher B_AES_256 = new CipherSuite.BulkCipher("AES/CBC/NoPadding", 32, 16, true);
   static final CipherSuite.BulkCipher B_SM1 = new CipherSuite.BulkCipher("SM1/CBC/NoPadding", 16, 16, true);
   static final CipherSuite.BulkCipher B_SM4 = new CipherSuite.BulkCipher("SM4/CBC/NoPadding", 16, 16, true);
   static final CipherSuite.MacAlg M_NULL = new CipherSuite.MacAlg("NULL", 0);
   static final CipherSuite.MacAlg M_MD5 = new CipherSuite.MacAlg("MD5", 16);
   static final CipherSuite.MacAlg M_SHA = new CipherSuite.MacAlg("SHA", 20);
   static final CipherSuite.MacAlg M_SHA256 = new CipherSuite.MacAlg("SHA256", 32);
   static final CipherSuite.MacAlg M_SHA384 = new CipherSuite.MacAlg("SHA384", 48);
   static final CipherSuite.MacAlg M_SM3 = new CipherSuite.MacAlg("SM3", 32);
   static final CipherSuite C_NULL;
   static final CipherSuite C_SCSV;

   static {
      boolean var0 = false;
      boolean var1 = true;
      boolean var2 = !MyJSSE.isFIPS();
      add("SSL_NULL_WITH_NULL_NULL", 0, 1, CipherSuite.KeyExchange.K_NULL, B_NULL, false);
      short var3 = 600;
      char var4 = '\uffff';
      int var5 = ProtocolVersion.TLS11.v;
      int var6 = ProtocolVersion.TLS12.v;
      int var7 = var3 - 1;
      add("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", 49188, var7, CipherSuite.KeyExchange.K_ECDHE_ECDSA, B_AES_256, true, var4, var6, CipherSuite.PRF.P_SHA384);
      --var7;
      add("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", 49192, var7, CipherSuite.KeyExchange.K_ECDHE_RSA, B_AES_256, true, var4, var6, CipherSuite.PRF.P_SHA384);
      --var7;
      add("TLS_RSA_WITH_AES_256_CBC_SHA256", 61, var7, CipherSuite.KeyExchange.K_RSA, B_AES_256, true, var4, var6, CipherSuite.PRF.P_SHA256);
      --var7;
      add("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", 49190, var7, CipherSuite.KeyExchange.K_ECDH_ECDSA, B_AES_256, true, var4, var6, CipherSuite.PRF.P_SHA384);
      --var7;
      add("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", 49194, var7, CipherSuite.KeyExchange.K_ECDH_RSA, B_AES_256, true, var4, var6, CipherSuite.PRF.P_SHA384);
      --var7;
      add("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", 107, var7, CipherSuite.KeyExchange.K_DHE_RSA, B_AES_256, true, var4, var6, CipherSuite.PRF.P_SHA256);
      --var7;
      add("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", 106, var7, CipherSuite.KeyExchange.K_DHE_DSS, B_AES_256, true, var4, var6, CipherSuite.PRF.P_SHA256);
      --var7;
      add("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", 49162, var7, CipherSuite.KeyExchange.K_ECDHE_ECDSA, B_AES_256, true);
      --var7;
      add("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 49172, var7, CipherSuite.KeyExchange.K_ECDHE_RSA, B_AES_256, true);
      --var7;
      add("TLS_RSA_WITH_AES_256_CBC_SHA", 53, var7, CipherSuite.KeyExchange.K_RSA, B_AES_256, true);
      --var7;
      add("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", 49157, var7, CipherSuite.KeyExchange.K_ECDH_ECDSA, B_AES_256, true);
      --var7;
      add("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", 49167, var7, CipherSuite.KeyExchange.K_ECDH_RSA, B_AES_256, true);
      --var7;
      add("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 57, var7, CipherSuite.KeyExchange.K_DHE_RSA, B_AES_256, true);
      --var7;
      add("TLS_DHE_DSS_WITH_AES_256_CBC_SHA", 56, var7, CipherSuite.KeyExchange.K_DHE_DSS, B_AES_256, true);
      --var7;
      add("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 49187, var7, CipherSuite.KeyExchange.K_ECDHE_ECDSA, B_AES_128, true, var4, var6, CipherSuite.PRF.P_SHA256);
      --var7;
      add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 49191, var7, CipherSuite.KeyExchange.K_ECDHE_RSA, B_AES_128, true, var4, var6, CipherSuite.PRF.P_SHA256);
      --var7;
      add("TLS_RSA_WITH_AES_128_CBC_SHA256", 60, var7, CipherSuite.KeyExchange.K_RSA, B_AES_128, true, var4, var6, CipherSuite.PRF.P_SHA256);
      --var7;
      add("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", 49189, var7, CipherSuite.KeyExchange.K_ECDH_ECDSA, B_AES_128, true, var4, var6, CipherSuite.PRF.P_SHA256);
      --var7;
      add("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", 49193, var7, CipherSuite.KeyExchange.K_ECDH_RSA, B_AES_128, true, var4, var6, CipherSuite.PRF.P_SHA256);
      --var7;
      add("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", 103, var7, CipherSuite.KeyExchange.K_DHE_RSA, B_AES_128, true, var4, var6, CipherSuite.PRF.P_SHA256);
      --var7;
      add("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", 64, var7, CipherSuite.KeyExchange.K_DHE_DSS, B_AES_128, true, var4, var6, CipherSuite.PRF.P_SHA256);
      --var7;
      add("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 49161, var7, CipherSuite.KeyExchange.K_ECDHE_ECDSA, B_AES_128, true);
      --var7;
      add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 49171, var7, CipherSuite.KeyExchange.K_ECDHE_RSA, B_AES_128, true);
      --var7;
      add("TLS_RSA_WITH_AES_128_CBC_SHA", 47, var7, CipherSuite.KeyExchange.K_RSA, B_AES_128, true);
      --var7;
      add("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", 49156, var7, CipherSuite.KeyExchange.K_ECDH_ECDSA, B_AES_128, true);
      --var7;
      add("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", 49166, var7, CipherSuite.KeyExchange.K_ECDH_RSA, B_AES_128, true);
      --var7;
      add("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 51, var7, CipherSuite.KeyExchange.K_DHE_RSA, B_AES_128, true);
      --var7;
      add("TLS_DHE_DSS_WITH_AES_128_CBC_SHA", 50, var7, CipherSuite.KeyExchange.K_DHE_DSS, B_AES_128, true);
      --var7;
      add("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", 49159, var7, CipherSuite.KeyExchange.K_ECDHE_ECDSA, B_RC4_128, var2);
      --var7;
      add("TLS_ECDHE_RSA_WITH_RC4_128_SHA", 49169, var7, CipherSuite.KeyExchange.K_ECDHE_RSA, B_RC4_128, var2);
      --var7;
      add("SSL_RSA_WITH_RC4_128_SHA", 5, var7, CipherSuite.KeyExchange.K_RSA, B_RC4_128, var2);
      --var7;
      add("TLS_ECDH_ECDSA_WITH_RC4_128_SHA", 49154, var7, CipherSuite.KeyExchange.K_ECDH_ECDSA, B_RC4_128, var2);
      --var7;
      add("TLS_ECDH_RSA_WITH_RC4_128_SHA", 49164, var7, CipherSuite.KeyExchange.K_ECDH_RSA, B_RC4_128, var2);
      --var7;
      add("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", 49160, var7, CipherSuite.KeyExchange.K_ECDHE_ECDSA, B_3DES, true);
      --var7;
      add("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", 49170, var7, CipherSuite.KeyExchange.K_ECDHE_RSA, B_3DES, true);
      --var7;
      add("SSL_RSA_WITH_3DES_EDE_CBC_SHA", 10, var7, CipherSuite.KeyExchange.K_RSA, B_3DES, true);
      --var7;
      add("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", 49155, var7, CipherSuite.KeyExchange.K_ECDH_ECDSA, B_3DES, true);
      --var7;
      add("TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", 49165, var7, CipherSuite.KeyExchange.K_ECDH_RSA, B_3DES, true);
      --var7;
      add("SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA", 22, var7, CipherSuite.KeyExchange.K_DHE_RSA, B_3DES, true);
      --var7;
      add("SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA", 19, var7, CipherSuite.KeyExchange.K_DHE_DSS, B_3DES, var2);
      --var7;
      add("SSL_RSA_WITH_RC4_128_MD5", 4, var7, CipherSuite.KeyExchange.K_RSA, B_RC4_128, var2);
      --var7;
      add("TLS_EMPTY_RENEGOTIATION_INFO_SCSV", 255, var7, CipherSuite.KeyExchange.K_SCSV, B_NULL, true);
      --var7;
      add("ECDHE_SM1_SM3", 57345, var7, CipherSuite.KeyExchange.K_SM2_SM2, B_SM1, true, var6, var5, CipherSuite.PRF.P_NONE);
      --var7;
      add("ECC_SM1_SM3", 57347, var7, CipherSuite.KeyExchange.K_ECC, B_SM1, true, var6, var5, CipherSuite.PRF.P_NONE);
      --var7;
      add("RSA_SM1_SM3", 57353, var7, CipherSuite.KeyExchange.K_RSA, B_SM1, true, var6, var5, CipherSuite.PRF.P_NONE);
      --var7;
      add("RSA_SM1_SHA", 57354, var7, CipherSuite.KeyExchange.K_RSA, B_SM1, true, var6, var5, CipherSuite.PRF.P_NONE);
      --var7;
      add("ECC_SM4_SM3", 57363, var7, CipherSuite.KeyExchange.K_ECC, B_SM4, true, var6, var5, CipherSuite.PRF.P_NONE);
      --var7;
      add("ECDHE_SM4_SM3", 57361, var7, CipherSuite.KeyExchange.K_SM2_SM2, B_SM4, true, var6, var5, CipherSuite.PRF.P_NONE);
      --var7;
      add("RSA_SM4_SM3", 57369, var7, CipherSuite.KeyExchange.K_RSA, B_SM4, true, var6, var5, CipherSuite.PRF.P_NONE);
      --var7;
      add("RSA_SM4_SHA", 57370, var7, CipherSuite.KeyExchange.K_RSA, B_SM4, true, var6, var5, CipherSuite.PRF.P_NONE);
      --var7;
      add("ECC_SM4_GCM_SM3", 57427, var7, CipherSuite.KeyExchange.K_ECC, B_SM4, true, var6, var5, CipherSuite.PRF.P_NONE);
      var3 = 300;
      var7 = var3 - 1;
      add("TLS_DH_anon_WITH_AES_256_CBC_SHA256", 109, var7, CipherSuite.KeyExchange.K_DH_ANON, B_AES_256, var2, var4, var6, CipherSuite.PRF.P_SHA256);
      --var7;
      add("TLS_ECDH_anon_WITH_AES_256_CBC_SHA", 49177, var7, CipherSuite.KeyExchange.K_ECDH_ANON, B_AES_256, true);
      --var7;
      add("TLS_DH_anon_WITH_AES_256_CBC_SHA", 58, var7, CipherSuite.KeyExchange.K_DH_ANON, B_AES_256, var2);
      --var7;
      add("TLS_DH_anon_WITH_AES_128_CBC_SHA256", 108, var7, CipherSuite.KeyExchange.K_DH_ANON, B_AES_128, var2, var4, var6, CipherSuite.PRF.P_SHA256);
      --var7;
      add("TLS_ECDH_anon_WITH_AES_128_CBC_SHA", 49176, var7, CipherSuite.KeyExchange.K_ECDH_ANON, B_AES_128, true);
      --var7;
      add("TLS_DH_anon_WITH_AES_128_CBC_SHA", 52, var7, CipherSuite.KeyExchange.K_DH_ANON, B_AES_128, var2);
      --var7;
      add("TLS_ECDH_anon_WITH_RC4_128_SHA", 49174, var7, CipherSuite.KeyExchange.K_ECDH_ANON, B_RC4_128, var2);
      --var7;
      add("SSL_DH_anon_WITH_RC4_128_MD5", 24, var7, CipherSuite.KeyExchange.K_DH_ANON, B_RC4_128, var2);
      --var7;
      add("TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", 49175, var7, CipherSuite.KeyExchange.K_ECDH_ANON, B_3DES, true);
      --var7;
      add("SSL_DH_anon_WITH_3DES_EDE_CBC_SHA", 27, var7, CipherSuite.KeyExchange.K_DH_ANON, B_3DES, var2);
      --var7;
      add("TLS_RSA_WITH_NULL_SHA256", 59, var7, CipherSuite.KeyExchange.K_RSA, B_NULL, var2, var4, var6, CipherSuite.PRF.P_SHA256);
      --var7;
      add("TLS_ECDHE_ECDSA_WITH_NULL_SHA", 49158, var7, CipherSuite.KeyExchange.K_ECDHE_ECDSA, B_NULL, var2);
      --var7;
      add("TLS_ECDHE_RSA_WITH_NULL_SHA", 49168, var7, CipherSuite.KeyExchange.K_ECDHE_RSA, B_NULL, var2);
      --var7;
      add("SSL_RSA_WITH_NULL_SHA", 2, var7, CipherSuite.KeyExchange.K_RSA, B_NULL, var2);
      --var7;
      add("TLS_ECDH_ECDSA_WITH_NULL_SHA", 49153, var7, CipherSuite.KeyExchange.K_ECDH_ECDSA, B_NULL, var2);
      --var7;
      add("TLS_ECDH_RSA_WITH_NULL_SHA", 49163, var7, CipherSuite.KeyExchange.K_ECDH_RSA, B_NULL, var2);
      --var7;
      add("TLS_ECDH_anon_WITH_NULL_SHA", 49173, var7, CipherSuite.KeyExchange.K_ECDH_ANON, B_NULL, var2);
      --var7;
      add("SSL_RSA_WITH_NULL_MD5", 1, var7, CipherSuite.KeyExchange.K_RSA, B_NULL, var2);
      --var7;
      add("SSL_RSA_WITH_DES_CBC_SHA", 9, var7, CipherSuite.KeyExchange.K_RSA, B_DES, var2, var6);
      --var7;
      add("SSL_DHE_RSA_WITH_DES_CBC_SHA", 21, var7, CipherSuite.KeyExchange.K_DHE_RSA, B_DES, var2, var6);
      --var7;
      add("SSL_DHE_DSS_WITH_DES_CBC_SHA", 18, var7, CipherSuite.KeyExchange.K_DHE_DSS, B_DES, var2, var6);
      --var7;
      add("SSL_DH_anon_WITH_DES_CBC_SHA", 26, var7, CipherSuite.KeyExchange.K_DH_ANON, B_DES, var2, var6);
      --var7;
      add("SSL_RSA_EXPORT_WITH_RC4_40_MD5", 3, var7, CipherSuite.KeyExchange.K_RSA_EXPORT, B_RC4_40, var2, var5);
      --var7;
      add("SSL_DH_anon_EXPORT_WITH_RC4_40_MD5", 23, var7, CipherSuite.KeyExchange.K_DH_ANON, B_RC4_40, var2, var5);
      --var7;
      add("SSL_RSA_EXPORT_WITH_DES40_CBC_SHA", 8, var7, CipherSuite.KeyExchange.K_RSA_EXPORT, B_DES_40, var2, var5);
      --var7;
      add("SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", 20, var7, CipherSuite.KeyExchange.K_DHE_RSA, B_DES_40, var2, var5);
      --var7;
      add("SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", 17, var7, CipherSuite.KeyExchange.K_DHE_DSS, B_DES_40, var2, var5);
      --var7;
      add("SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA", 25, var7, CipherSuite.KeyExchange.K_DH_ANON, B_DES_40, var2, var5);
      --var7;
      add("TLS_KRB5_WITH_RC4_128_SHA", 32, var7, CipherSuite.KeyExchange.K_KRB5, B_RC4_128, var2);
      --var7;
      add("TLS_KRB5_WITH_RC4_128_MD5", 36, var7, CipherSuite.KeyExchange.K_KRB5, B_RC4_128, var2);
      --var7;
      add("TLS_KRB5_WITH_3DES_EDE_CBC_SHA", 31, var7, CipherSuite.KeyExchange.K_KRB5, B_3DES, var2);
      --var7;
      add("TLS_KRB5_WITH_3DES_EDE_CBC_MD5", 35, var7, CipherSuite.KeyExchange.K_KRB5, B_3DES, var2);
      --var7;
      add("TLS_KRB5_WITH_DES_CBC_SHA", 30, var7, CipherSuite.KeyExchange.K_KRB5, B_DES, var2, var6);
      --var7;
      add("TLS_KRB5_WITH_DES_CBC_MD5", 34, var7, CipherSuite.KeyExchange.K_KRB5, B_DES, var2, var6);
      --var7;
      add("TLS_KRB5_EXPORT_WITH_RC4_40_SHA", 40, var7, CipherSuite.KeyExchange.K_KRB5_EXPORT, B_RC4_40, var2, var5);
      --var7;
      add("TLS_KRB5_EXPORT_WITH_RC4_40_MD5", 43, var7, CipherSuite.KeyExchange.K_KRB5_EXPORT, B_RC4_40, var2, var5);
      --var7;
      add("TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA", 38, var7, CipherSuite.KeyExchange.K_KRB5_EXPORT, B_DES_40, var2, var5);
      --var7;
      add("TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5", 41, var7, CipherSuite.KeyExchange.K_KRB5_EXPORT, B_DES_40, var2, var5);
      add("SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5", 6);
      add("SSL_RSA_WITH_IDEA_CBC_SHA", 7);
      add("SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", 11);
      add("SSL_DH_DSS_WITH_DES_CBC_SHA", 12);
      add("SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA", 13);
      add("SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", 14);
      add("SSL_DH_RSA_WITH_DES_CBC_SHA", 15);
      add("SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA", 16);
      add("SSL_FORTEZZA_DMS_WITH_NULL_SHA", 28);
      add("SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA", 29);
      add("SSL_RSA_EXPORT1024_WITH_DES_CBC_SHA", 98);
      add("SSL_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA", 99);
      add("SSL_RSA_EXPORT1024_WITH_RC4_56_SHA", 100);
      add("SSL_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA", 101);
      add("SSL_DHE_DSS_WITH_RC4_128_SHA", 102);
      add("NETSCAPE_RSA_FIPS_WITH_3DES_EDE_CBC_SHA", 65504);
      add("NETSCAPE_RSA_FIPS_WITH_DES_CBC_SHA", 65505);
      add("SSL_RSA_FIPS_WITH_DES_CBC_SHA", 65278);
      add("SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA", 65279);
      add("TLS_KRB5_WITH_IDEA_CBC_SHA", 33);
      add("TLS_KRB5_WITH_IDEA_CBC_MD5", 37);
      add("TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA", 39);
      add("TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5", 42);
      add("TLS_RSA_WITH_SEED_CBC_SHA", 150);
      add("TLS_DH_DSS_WITH_SEED_CBC_SHA", 151);
      add("TLS_DH_RSA_WITH_SEED_CBC_SHA", 152);
      add("TLS_DHE_DSS_WITH_SEED_CBC_SHA", 153);
      add("TLS_DHE_RSA_WITH_SEED_CBC_SHA", 154);
      add("TLS_DH_anon_WITH_SEED_CBC_SHA", 155);
      add("TLS_PSK_WITH_RC4_128_SHA", 138);
      add("TLS_PSK_WITH_3DES_EDE_CBC_SHA", 139);
      add("TLS_PSK_WITH_AES_128_CBC_SHA", 140);
      add("TLS_PSK_WITH_AES_256_CBC_SHA", 141);
      add("TLS_DHE_PSK_WITH_RC4_128_SHA", 142);
      add("TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA", 143);
      add("TLS_DHE_PSK_WITH_AES_128_CBC_SHA", 144);
      add("TLS_DHE_PSK_WITH_AES_256_CBC_SHA", 145);
      add("TLS_RSA_PSK_WITH_RC4_128_SHA", 146);
      add("TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA", 147);
      add("TLS_RSA_PSK_WITH_AES_128_CBC_SHA", 148);
      add("TLS_RSA_PSK_WITH_AES_256_CBC_SHA", 149);
      add("TLS_PSK_WITH_NULL_SHA", 44);
      add("TLS_DHE_PSK_WITH_NULL_SHA", 45);
      add("TLS_RSA_PSK_WITH_NULL_SHA", 46);
      add("TLS_DH_DSS_WITH_AES_128_CBC_SHA", 48);
      add("TLS_DH_RSA_WITH_AES_128_CBC_SHA", 49);
      add("TLS_DH_DSS_WITH_AES_256_CBC_SHA", 54);
      add("TLS_DH_RSA_WITH_AES_256_CBC_SHA", 55);
      add("TLS_DH_DSS_WITH_AES_128_CBC_SHA256", 62);
      add("TLS_DH_RSA_WITH_AES_128_CBC_SHA256", 63);
      add("TLS_DH_DSS_WITH_AES_256_CBC_SHA256", 104);
      add("TLS_DH_RSA_WITH_AES_256_CBC_SHA256", 105);
      add("TLS_RSA_WITH_AES_128_GCM_SHA256", 156);
      add("TLS_RSA_WITH_AES_256_GCM_SHA384", 157);
      add("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 158);
      add("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 159);
      add("TLS_DH_RSA_WITH_AES_128_GCM_SHA256", 160);
      add("TLS_DH_RSA_WITH_AES_256_GCM_SHA384", 161);
      add("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", 162);
      add("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", 163);
      add("TLS_DH_DSS_WITH_AES_128_GCM_SHA256", 164);
      add("TLS_DH_DSS_WITH_AES_256_GCM_SHA384", 165);
      add("TLS_DH_anon_WITH_AES_128_GCM_SHA256", 166);
      add("TLS_DH_anon_WITH_AES_256_GCM_SHA384", 167);
      add("TLS_PSK_WITH_AES_128_GCM_SHA256", 168);
      add("TLS_PSK_WITH_AES_256_GCM_SHA384", 169);
      add("TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", 170);
      add("TLS_DHE_PSK_WITH_AES_256_GCM_SHA384", 171);
      add("TLS_RSA_PSK_WITH_AES_128_GCM_SHA256", 172);
      add("TLS_RSA_PSK_WITH_AES_256_GCM_SHA384", 173);
      add("TLS_PSK_WITH_AES_128_CBC_SHA256", 174);
      add("TLS_PSK_WITH_AES_256_CBC_SHA384", 175);
      add("TLS_PSK_WITH_NULL_SHA256", 176);
      add("TLS_PSK_WITH_NULL_SHA384", 177);
      add("TLS_DHE_PSK_WITH_AES_128_CBC_SHA256", 178);
      add("TLS_DHE_PSK_WITH_AES_256_CBC_SHA384", 179);
      add("TLS_DHE_PSK_WITH_NULL_SHA256", 180);
      add("TLS_DHE_PSK_WITH_NULL_SHA384", 181);
      add("TLS_RSA_PSK_WITH_AES_128_CBC_SHA256", 182);
      add("TLS_RSA_PSK_WITH_AES_256_CBC_SHA384", 183);
      add("TLS_RSA_PSK_WITH_NULL_SHA256", 184);
      add("TLS_RSA_PSK_WITH_NULL_SHA384", 185);
      add("TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", 65);
      add("TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA", 66);
      add("TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA", 67);
      add("TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", 68);
      add("TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", 69);
      add("TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", 70);
      add("TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", 132);
      add("TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA", 133);
      add("TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA", 134);
      add("TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", 135);
      add("TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", 136);
      add("TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA", 137);
      add("TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", 186);
      add("TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256", 187);
      add("TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256", 188);
      add("TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256", 189);
      add("TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", 190);
      add("TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256", 191);
      add("TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", 192);
      add("TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256", 193);
      add("TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256", 194);
      add("TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256", 195);
      add("TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", 196);
      add("TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256", 197);
      add("TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA", 49178);
      add("TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA", 49179);
      add("TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA", 49180);
      add("TLS_SRP_SHA_WITH_AES_128_CBC_SHA", 49181);
      add("TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA", 49182);
      add("TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA", 49183);
      add("TLS_SRP_SHA_WITH_AES_256_CBC_SHA", 49184);
      add("TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA", 49185);
      add("TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA", 49186);
      add("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 49195);
      add("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 49196);
      add("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", 49197);
      add("TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", 49198);
      add("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 49199);
      add("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 49200);
      add("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", 49201);
      add("TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", 49202);
      add("TLS_ECDHE_PSK_WITH_RC4_128_SHA", 49203);
      add("TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA", 49204);
      add("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", 49205);
      add("TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA", 49206);
      add("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", 49207);
      add("TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384", 49208);
      add("TLS_ECDHE_PSK_WITH_NULL_SHA", 49209);
      add("TLS_ECDHE_PSK_WITH_NULL_SHA256", 49210);
      add("TLS_ECDHE_PSK_WITH_NULL_SHA384", 49211);
      C_NULL = valueOf(0, 0);
      C_SCSV = valueOf(0, 255);
   }

   private CipherSuite(String var1, int var2, int var3, CipherSuite.KeyExchange var4, CipherSuite.BulkCipher var5, boolean var6, int var7, int var8, CipherSuite.PRF var9) {
      this.name = var1;
      this.id = var2;
      this.priority = var3;
      this.keyExchange = var4;
      this.cipher = var5;
      this.exportable = var5.exportable;
      if (var1.endsWith("_MD5")) {
         this.macAlg = M_MD5;
      } else if (var1.endsWith("_SHA")) {
         this.macAlg = M_SHA;
      } else if (var1.endsWith("_SM3")) {
         this.macAlg = M_SM3;
      } else if (var1.endsWith("_SHA256")) {
         this.macAlg = M_SHA256;
      } else if (var1.endsWith("_SHA384")) {
         this.macAlg = M_SHA384;
      } else if (var1.endsWith("_NULL")) {
         this.macAlg = M_NULL;
      } else {
         if (!var1.endsWith("_SCSV")) {
            throw new IllegalArgumentException("Unknown MAC algorithm for ciphersuite " + var1);
         }

         this.macAlg = M_NULL;
      }

      var6 &= var4.allowed;
      var6 &= var5.allowed;
      this.allowed = var6;
      this.obsoleted = var7;
      this.supported = var8;
      this.prfAlg = var9;
      if (GMConf.debug) {
         System.out.println("suite.name()=" + var1 + ",suite.supported=" + var8);
      }

   }

   private CipherSuite(String var1, int var2) {
      this.name = var1;
      this.id = var2;
      this.allowed = false;
      this.priority = 0;
      this.keyExchange = null;
      this.cipher = null;
      this.macAlg = null;
      this.exportable = false;
      this.obsoleted = 65535;
      this.supported = 769;
      this.prfAlg = CipherSuite.PRF.P_NONE;
   }

   boolean isAvailable() {
      return this.allowed && this.keyExchange.isAvailable() && this.cipher.isAvailable();
   }

   boolean isNegotiable() {
      return this != C_SCSV && this.isAvailable();
   }

   public int compareTo(Object var1) {
      return ((CipherSuite)var1).priority - this.priority;
   }

   public String toString() {
      return this.name;
   }

   static CipherSuite valueOf(String var0) {
      if (var0 == null) {
         throw new IllegalArgumentException("Name must not be null");
      } else {
         CipherSuite var1 = (CipherSuite)nameMap.get(var0);
         if (var1 != null && var1.allowed) {
            return var1;
         } else {
            throw new IllegalArgumentException("Unsupported ciphersuite " + var0);
         }
      }
   }

   static CipherSuite valueOf(int var0, int var1) {
      var0 &= 255;
      var1 &= 255;
      int var2 = var0 << 8 | var1;
      CipherSuite var3 = (CipherSuite)idMap.get(var2);
      if (var3 == null) {
         String var4 = Integer.toString(var0, 16);
         String var5 = Integer.toString(var1, 16);
         var3 = new CipherSuite("Unknown 0x" + var4 + ":0x" + var5, var2);
      }

      return var3;
   }

   static Collection<CipherSuite> allowedCipherSuites() {
      return nameMap.values();
   }

   private static void add(String var0, int var1, int var2, CipherSuite.KeyExchange var3, CipherSuite.BulkCipher var4, boolean var5, int var6, int var7, CipherSuite.PRF var8) {
      CipherSuite var9 = new CipherSuite(var0, var1, var2, var3, var4, var5, var6, var7, var8);
      if (idMap.put(var1, var9) != null) {
         throw new RuntimeException("Duplicate ciphersuite definition: " + var1 + ", " + var0);
      } else if (var9.allowed && nameMap.put(var0, var9) != null) {
         throw new RuntimeException("Duplicate ciphersuite definition: " + var1 + ", " + var0);
      }
   }

   private static void add(String var0, int var1, int var2, CipherSuite.KeyExchange var3, CipherSuite.BulkCipher var4, boolean var5, int var6) {
      CipherSuite.PRF var7 = CipherSuite.PRF.P_SHA256;
      if (var6 < ProtocolVersion.TLS12.v) {
         var7 = CipherSuite.PRF.P_NONE;
      }

      add(var0, var1, var2, var3, var4, var5, var6, 769, var7);
   }

   private static void add(String var0, int var1, int var2, CipherSuite.KeyExchange var3, CipherSuite.BulkCipher var4, boolean var5) {
      add(var0, var1, var2, var3, var4, var5, 65535);
   }

   private static void add(String var0, int var1) {
      CipherSuite var2 = new CipherSuite(var0, var1);
      if (idMap.put(var1, var2) != null) {
         throw new RuntimeException("Duplicate ciphersuite definition: " + var1 + ", " + var0);
      }
   }

   static final class BulkCipher {
      private static final Map<CipherSuite.BulkCipher, Boolean> availableCache = new HashMap(8);
      final String description;
      final String transformation;
      final String algorithm;
      final boolean allowed;
      final int keySize;
      final int expandedKeySize;
      final int ivSize;
      final boolean exportable;

      BulkCipher(String var1, int var2, int var3, int var4, boolean var5) {
         this.transformation = var1;
         this.algorithm = var1.split("/")[0];
         this.description = this.algorithm + "/" + (var2 << 3);
         this.keySize = var2;
         this.ivSize = var4;
         this.allowed = var5;
         this.expandedKeySize = var3;
         this.exportable = true;
      }

      BulkCipher(String var1, int var2, int var3, boolean var4) {
         this.transformation = var1;
         this.algorithm = var1.split("/")[0];
         this.description = this.algorithm + "/" + (var2 << 3);
         this.keySize = var2;
         this.ivSize = var3;
         this.allowed = var4;
         this.expandedKeySize = var2;
         this.exportable = false;
      }

      CipherBox newCipher(ProtocolVersion var1, SecretKey var2, IvParameterSpec var3, SecureRandom var4, boolean var5) throws NoSuchAlgorithmException {
         return CipherBox.newCipherBox(var1, this, var2, var3, var4, var5);
      }

      boolean isAvailable() {
         if (!this.allowed) {
            return false;
         } else {
            return this == CipherSuite.B_AES_256 ? isAvailable(this) : true;
         }
      }

      static synchronized void clearAvailableCache() {
         availableCache.clear();
      }

      private static synchronized boolean isAvailable(CipherSuite.BulkCipher var0) {
         Boolean var1 = (Boolean)availableCache.get(var0);
         if (var1 == null) {
            try {
               SecretKeySpec var2 = new SecretKeySpec(new byte[var0.expandedKeySize], var0.algorithm);
               IvParameterSpec var3 = new IvParameterSpec(new byte[var0.ivSize]);
               var0.newCipher(ProtocolVersion.DEFAULT, var2, var3, (SecureRandom)null, true);
               var1 = Boolean.TRUE;
            } catch (NoSuchAlgorithmException var4) {
               var1 = Boolean.FALSE;
            }

            availableCache.put(var0, var1);
         }

         return var1;
      }

      public String toString() {
         return this.description;
      }
   }

   static enum KeyExchange {
      K_NULL("NULL", false),
      K_RSA("RSA", true),
      K_RSA_EXPORT("RSA_EXPORT", true),
      K_DH_RSA("DH_RSA", false),
      K_DH_DSS("DH_DSS", false),
      K_DHE_DSS("DHE_DSS", true),
      K_DHE_RSA("DHE_RSA", true),
      K_DH_ANON("DH_anon", true),
      K_ECDH_ECDSA("ECDH_ECDSA", CipherSuite.ALLOW_ECC),
      K_ECDH_RSA("ECDH_RSA", CipherSuite.ALLOW_ECC),
      K_ECDHE_ECDSA("ECDHE_ECDSA", CipherSuite.ALLOW_ECC),
      K_ECDHE_RSA("ECDHE_RSA", CipherSuite.ALLOW_ECC),
      K_ECDH_ANON("ECDH_anon", CipherSuite.ALLOW_ECC),
      K_SM2_SM2("SM2_SM2", CipherSuite.ALLOW_ECC),
      K_ECC("ECC", CipherSuite.ALLOW_ECC),
      K_KRB5("KRB5", true),
      K_KRB5_EXPORT("KRB5_EXPORT", true),
      K_SCSV("SCSV", true);

      final String name;
      final boolean allowed;
      private final boolean alwaysAvailable;

      private KeyExchange(String var3, boolean var4) {
         this.name = var3;
         this.allowed = var4;
         this.alwaysAvailable = var4 && !var3.startsWith("EC") && !var3.startsWith("KRB");
      }

      boolean isAvailable() {
         if (this.alwaysAvailable) {
            return true;
         } else if (this.name.startsWith("EC")) {
            return this.allowed && JsseJce.isEcAvailable();
         } else if (this.name.startsWith("KRB")) {
            return this.allowed && JsseJce.isKerberosAvailable();
         } else {
            return this.allowed;
         }
      }

      public String toString() {
         return this.name;
      }
   }

   static final class MacAlg {
      final String name;
      final int size;

      MacAlg(String var1, int var2) {
         this.name = var1;
         this.size = var2;
      }

      MAC newMac(ProtocolVersion var1, SecretKey var2) throws NoSuchAlgorithmException, InvalidKeyException {
         return new MAC(this, var1, var2);
      }

      public String toString() {
         return this.name;
      }
   }

   static enum PRF {
      P_NONE("NONE", 0, 0),
      P_SHA256("SHA-256", 32, 64),
      P_SHA384("SHA-384", 48, 128),
      P_SHA512("SHA-512", 64, 128);

      private final String prfHashAlg;
      private final int prfHashLength;
      private final int prfBlockSize;

      private PRF(String var3, int var4, int var5) {
         this.prfHashAlg = var3;
         this.prfHashLength = var4;
         this.prfBlockSize = var5;
      }

      String getPRFHashAlg() {
         return this.prfHashAlg;
      }

      int getPRFHashLength() {
         return this.prfHashLength;
      }

      int getPRFBlockSize() {
         return this.prfBlockSize;
      }
   }
}
