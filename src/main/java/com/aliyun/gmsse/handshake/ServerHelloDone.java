package com.aliyun.gmsse.handshake;

import java.io.*;

import com.aliyun.gmsse.record.Handshake;
import com.aliyun.gmsse.record.Handshake.Body;

public class ServerHelloDone extends Handshake.Body {

    @Override
    public byte[] getBytes() throws IOException {
        return new byte[0];
    }

    @Override
    public void print(PrintStream out) {

    }

    public static Body read(InputStream input) {
        return new ServerHelloDone();
    }

    @Override
    public String toString() {
        StringWriter str = new StringWriter();
        PrintWriter out = new PrintWriter(str);
        out.println("struct {");
        out.println("} ServerHelloDone;");
        return str.toString();
    }

}
