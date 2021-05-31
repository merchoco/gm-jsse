package com.aliyun.gmsse;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

public class TestMain {

    public static void main(String[] args) throws Exception {
        // init SSLSocketFactory
        GMProvider provider = new GMProvider();
  /*      BouncyCastleProvider bc = new BouncyCastleProvider();
        KeyStore ks = KeyStore.getInstance("JKS");
        CertificateFactory cf = CertificateFactory.getInstance("X.509", bc);
        FileInputStream is = new FileInputStream("/path/to/ca_cert");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        ks.load(null, null);
        ks.setCertificateEntry("gmca", cert);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509", provider);
        tmf.init(ks);*/


       //SSLContext sc = SSLContext.getInstance("TLS", provider);
        javax.net.ssl.SSLContext sc = createIgnoreVerifySSL(provider);
        sc.init(null, null, null);
        SSLSocketFactory ssf = sc.getSocketFactory();

        URL serverUrl = new URL("https://sm2test.ovssl.cn/");
        HttpsURLConnection conn = (HttpsURLConnection) serverUrl.openConnection();
        conn.setRequestMethod("GET");
        // set SSLSocketFactory
        conn.setSSLSocketFactory(ssf);
        conn.connect();
        System.out.println("used cipher suite:");
        System.out.println(conn.getCipherSuite());
    }

    // 创建SSL上下文---忽略服务端证书信任
    static javax.net.ssl.SSLContext createIgnoreVerifySSL( GMProvider provider ) throws NoSuchAlgorithmException, KeyManagementException, NoSuchProviderException
    {
        //javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance(cn.gmssl.jsse.provider.GMJSSE.GMSSLv11, cn.gmssl.jsse.provider.GMJSSE.NAME);
        javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("TLS", provider);
        // 实现一个X509TrustManager接口，用于绕过验证，不用修改里面的方法
        X509TrustManager trustManager = new X509TrustManager()
        {
            @Override
            public void checkClientTrusted(java.security.cert.X509Certificate[] paramArrayOfX509Certificate, String paramString) throws CertificateException
            {
                for (int i = 0; i < paramArrayOfX509Certificate.length; i++)
                {
                    System.out.println(paramArrayOfX509Certificate[i].getSubjectDN().getName());
                }
                System.out.println("");
            }

            @Override
            public void checkServerTrusted(java.security.cert.X509Certificate[] paramArrayOfX509Certificate, String paramString) throws CertificateException
            {
                for (int i = 0; i < paramArrayOfX509Certificate.length; i++)
                {
                    System.out.println(paramArrayOfX509Certificate[i].getSubjectDN().getName());
                }
                System.out.println("");
            }

            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers()
            {
                return null;
            }
        };

        return sc;
    }
}
