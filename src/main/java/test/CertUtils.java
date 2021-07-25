package test;

import com.aliyun.gmsse.GMProvider;
import com.aliyun.gmsse.SunX509KeyManagerImpl;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

public class CertUtils {

   public static   SSLContext ctx;
    private static SunX509KeyManagerImpl keyManager;

    public static SSLContext getCtx() throws Exception {
        GMProvider provider = new GMProvider();
        KeyStore keyStore = KeyStore.getInstance("PKCS12", provider);
        keyStore.load(new FileInputStream(
                        "D:\\dev\\dev2\\gm-jsse\\examples\\src\\main\\resources\\keystore\\sm2.server1.both.pfx"),
                "12345678".toCharArray());
        keyManager = new SunX509KeyManagerImpl(keyStore,"12345678".toCharArray());
        ctx = SSLContext.getInstance("TLS", provider);
        java.security.SecureRandom secureRandom = new java.security.SecureRandom();
        ctx.init(
                new KeyManager[]{keyManager},
                new TrustManager[]{new TrustAllManager()},
                secureRandom);
       return ctx;
    }

    public static X509Certificate[] getCert(){
        X509Certificate[] var18 = keyManager.getCertificateChain("Sig");
        X509Certificate[] var19 = keyManager.getCertificateChain("Enc");

        //PrivateKey var17 = keyManager.getPrivateKey("Sig");
        // PrivateKey var16 = keyManager.getPrivateKey("Enc");

        X509Certificate[] certs = new X509Certificate[4];
        certs[0] = var18[0];
        certs[1] = var19[0];

        for (int i = 0; i < var18.length - 1; ++i) {
            certs[2 + i] = var18[1 + i];
        }
        return certs;
    }

}
