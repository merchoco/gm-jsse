package test;

import java.security.cert.X509Certificate;
import javax.net.ssl.*;

public class TrustAllManager implements X509TrustManager
{
	   private X509Certificate[] issuers;

	   public TrustAllManager()
	   {
	       this.issuers = new X509Certificate[0];
	   }

	   public X509Certificate[] getAcceptedIssuers()
	   {
	       return issuers ;
	   }

	   public void checkClientTrusted(X509Certificate[] chain, String authType)
	   {}

	   public void checkServerTrusted(X509Certificate[] chain, String authType)
	   {}
}