package client;

import java.net.*;
import java.io.*;
import java.security.*;

import javax.net.SocketFactory;
import javax.net.ssl.*;

public class Client1
{
	public Client1()
	{}

	public static void main(String[] args)
	{
		SocketFactory fact = null;
		SSLSocket socket = null;
		try
		{
			String addr = "localhost";
			int port = 8441;
			Security.insertProviderAt(new cn.gmssl.jce.provider.GMJCE(), 1);
			Security.insertProviderAt(new cn.gmssl.jsse.provider.GMJSSE(), 2);
			fact = createSocketFactory(null, null);
			socket = (SSLSocket) fact.createSocket();

			socket.setEnabledCipherSuites(new String[] {"ECC_SM4_SM3"});
			socket.setTcpNoDelay(true);

			socket.connect(new InetSocketAddress(addr, port), 2000);
			socket.setTcpNoDelay(true);
			socket.startHandshake();
			
			DataInputStream in = new DataInputStream(socket.getInputStream());
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            String s = "GET " + addr+":"+port + " HTTP/1.1\r\n";
            s+= "Accept: */*\r\n";
            s+= "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)\r\n";
            s+= "Host: " + addr + (port) + "\r\n";
            s+= "Connection: Close\r\n";
            s+= "\r\n";
            out.write(s.getBytes());
            out.flush();

			System.out.println(socket.getSession().getCipherSuite());
			
			byte[] buf = new byte[8192];
			int len = in.read(buf);
			if (len == -1)
			{
				System.out.println("eof");
				return;
			}
			System.out.println(new String(buf, 0, len));
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		finally
		{
			try
			{
				socket.close();
			}
			catch (Exception e)
			{}
		}
	}

	public static SSLSocketFactory createSocketFactory(KeyStore kepair, char[] pwd) throws Exception
	{
		TrustAllManager[] trust = { new TrustAllManager() };

		KeyManager[] kms = null;
		if (kepair != null)
		{
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(kepair, pwd);
			kms = kmf.getKeyManagers();
		}

		SSLContext ctx = SSLContext.getInstance("GMSSLv1.1", "GMJSSE");
		java.security.SecureRandom secureRandom = new java.security.SecureRandom();
		ctx.init(kms, trust, secureRandom);
		ctx.getServerSessionContext().setSessionCacheSize(8192);
		ctx.getServerSessionContext().setSessionTimeout(3600);

		SSLSocketFactory factory = ctx.getSocketFactory();
		return factory;
	}
}
