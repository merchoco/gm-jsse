package com.aliyun.gmsse.handshake;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import com.aliyun.gmsse.ProtocolVersion;
import com.aliyun.gmsse.CipherSuite;
import com.aliyun.gmsse.CompressionMethod;
import com.aliyun.gmsse.ClientRandom;
import com.aliyun.gmsse.Util;
import com.aliyun.gmsse.record.Handshake;
import com.aliyun.gmsse.record.Handshake.Body;

public class ClientHello extends Handshake.Body {
    ClientRandom random;
    byte[] sessionId;
    private List<CipherSuite> suites;
    private List<CompressionMethod> compressions;
    private ProtocolVersion version;

    public ClientHello(ProtocolVersion version, ClientRandom random, byte[] sessionId, List<CipherSuite> suites,
                       List<CompressionMethod> compressions) {
        this.version = version;
        this.random = random;
        this.sessionId = sessionId;
        this.suites = suites;
        this.compressions = compressions;
    }

    @Override
    public String toString() {
        StringWriter str = new StringWriter();
        PrintWriter out = new PrintWriter(str);
        out.println("struct {");
        out.println("  version = " + version + ";");
        BufferedReader r = new BufferedReader(new StringReader(random.toString()));
        String s;
        try {
            while ((s = r.readLine()) != null) {
                out.print("  ");
                out.println(s);
            }
        } catch (IOException ignored) {
        }
        out.println("  sessionId = " + Util.hexString(sessionId) + ";");
        out.println("  cipherSuites = {");
        for (Iterator<CipherSuite> i = suites.iterator(); i.hasNext(); ) {
            out.print("    ");
            out.println(i.next().getName());
        }
        out.println("  };");
        out.print("  compressionMethods = { ");
        for (Iterator<CompressionMethod> i = compressions.iterator(); i.hasNext(); ) {
            out.print(i.next().toString());
            if (i.hasNext()) {
                out.print(", ");
            }
        }
        out.println(" };");
        out.println("} ClientHello;");
        return str.toString();
    }

    @Override
    public byte[] getBytes() throws IOException {
        ByteArrayOutputStream ba = new ByteArrayOutputStream();
        // write version
        ba.write(version.getMajor());
        ba.write(version.getMinor());
        // write random
        ba.write(random.getBytes());
        // write cipher suites
        int length = suites.size() * 4;
        ba.write(length >>> 16 & 0xFF);
        ba.write(length >>> 8 & 0xFF);
        ba.write(length & 0xFF);
        for (CipherSuite suite : suites) {
            ba.write(suite.getId());
            ba.write(suite.getKeyLength() >>> 8 & 0xFF);
            ba.write(suite.getKeyLength() & 0xFF);
        }

        // write compress
        ba.write(compressions.size());
        for (CompressionMethod c : compressions) {
            ba.write(c.getValue());
        }

        return ba.toByteArray();
    }

    public static Body read(InputStream input) throws IOException {
        //读TLS协议版本

        ProtocolVersion version = ProtocolVersion.getInstance(
                input.read() & 0xff, input.read() & 0xff);
        if (version.compareTo(ProtocolVersion.NTLS_1_1) != 0) {

            //客户端clientHello不合法
        }
        //读随机数
        byte[] randomBytes = new byte[32];
        input.read(randomBytes, 0, 32);
        int gmtUnixTime = randomBytes[0] << 24;
        gmtUnixTime += randomBytes[1] << 16;
        gmtUnixTime += randomBytes[2] << 8;
        gmtUnixTime += randomBytes[3];
        System.out.println("time  :" + gmtUnixTime);
        ClientRandom random = new ClientRandom(gmtUnixTime, randomBytes);

        //读sessionId
        int sessionIdLen= input.read() & 0xff;
        byte[] sessionId = new byte[sessionIdLen];
        input.read(sessionId, 0, sessionIdLen);

         //读size
          int suiteSize=(input.read() & 0xFF)  << 8 | (input.read() & 0xFF );
          byte [] suiteBytes =new byte[suiteSize];
          input.read(suiteBytes, 0, suiteSize);

        List<CipherSuite> suites = new ArrayList<CipherSuite>();
        //每个密码套件2个字节
        for(int i= 0; i < suiteSize; i += 2) {
            byte id1 = suiteBytes[i];
            byte id2 = suiteBytes[i+1];
            CipherSuite suite = CipherSuite.values(id1, id2);
            suites.add(suite);
        }

        int compressionLength = input.read();

        List<CompressionMethod> compressions = new ArrayList<CompressionMethod>();
        for (int i = 0; i < compressionLength; i++) {
            compressions.add(CompressionMethod.getInstance(input.read() & 0xFF));
        }
        return new ClientHello(version, random, sessionId, suites, compressions);
    }

    public List<CipherSuite> getSuites() {
        return suites;
    }

    public void setSuites(List<CipherSuite> suites) {
        this.suites = suites;
    }

    public void print(PrintStream s) {

        System.out.println("****");
        System.out.println("RandomCookie : ");
        random.print(s);
        System.out.println("CipherSuite : ");
        for (CipherSuite suite : suites) {
            System.out.println("suiteName : " + suite.getName());
            System.out.println("version:  " + version);
        }


    }


    public ClientRandom getRandom() {
        return random;
    }

    public void setRandom(ClientRandom random) {
        this.random = random;
    }

    public byte[] getSessionId() {
        return sessionId;
    }

    public void setSessionId(byte[] sessionId) {
        this.sessionId = sessionId;
    }

    public List<CompressionMethod> getCompressions() {
        return compressions;
    }

    public void setCompressions(List<CompressionMethod> compressions) {
        this.compressions = compressions;
    }

    public ProtocolVersion getVersion() {
        return version;
    }

    public void setVersion(ProtocolVersion version) {
        this.version = version;
    }

    public void clientHello(Body body) {
        //
    }
}
