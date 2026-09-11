package com.arena.sentinel;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/** Decodes Android binary XML (AXML) back to readable XML — pure Java, JVM-testable. */
class AxmlDecoder {

    private ByteBuffer b;
    private String[] pool;
    private int indent = 0;
    private final StringBuilder out = new StringBuilder();

    String decode(byte[] data) {
        if (data == null || data.length < 8) return "";
        b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        int off = b.getShort(2) & 0xffff;
        if (off == 0) off = 8;
        int end = data.length;
        while (off + 8 <= end) {
            int type = b.getShort(off) & 0xffff;
            int headerSize = b.getShort(off + 2) & 0xffff;
            int size = b.getInt(off + 4);
            if (size <= 0 || off + size > end) break;
            if (type == 0x0001) parseStringPool(off);
            else if (type == 0x0102) parseStart(off, headerSize == 0 ? 8 : headerSize);
            else if (type == 0x0103) parseEnd(off, headerSize == 0 ? 8 : headerSize);
            // 0x0180 resource-map, 0x0100/0101 namespace, 0x0104 cdata -> skip
            off += size;
        }
        return out.toString();
    }

    private void parseStringPool(int chunkOff) {
        int stringCount = b.getInt(chunkOff + 8);
        int flags = b.getInt(chunkOff + 16);
        int stringsStart = b.getInt(chunkOff + 20);
        boolean utf8 = (flags & 0x100) != 0;
        int base = chunkOff + stringsStart;
        List<String> list = new ArrayList<>(stringCount);
        for (int i = 0; i < stringCount; i++) {
            int strOff = b.getInt(chunkOff + 28 + i * 4) + base;
            list.add(readString(strOff, utf8));
        }
        pool = list.toArray(new String[0]);
    }

    private String readString(int off, boolean utf8) {
        try {
            if (utf8) {
                int[] a = readU8pair(off);          // utf16 count (ignored)
                int[] c = readU8pair(a[1]);         // byte count
                int blen = c[0], p = c[1];
                if (blen < 0 || blen > 65535) return "";
                byte[] arr = new byte[blen];
                for (int i = 0; i < blen; i++) arr[i] = b.get(p + i);
                return new String(arr, "UTF-8");
            } else {
                int len = b.getShort(off) & 0xffff;
                int p = off + 2;
                if ((len & 0x8000) != 0) { len = ((len & 0x7fff) << 16) | (b.getShort(p) & 0xffff); p += 2; }
                if (len < 0 || len > 65535) return "";
                char[] arr = new char[len];
                for (int i = 0; i < len; i++) arr[i] = b.getChar(p + i * 2);
                return new String(arr);
            }
        } catch (Exception e) { return ""; }
    }

    private int[] readU8pair(int off) {
        int v = b.get(off) & 0xff;
        if ((v & 0x80) != 0) return new int[]{ ((v & 0x7f) << 8) | (b.get(off + 1) & 0xff), off + 2 };
        return new int[]{ v, off + 1 };
    }

    private void parseStart(int chunkOff, int hs) {
        int name = b.getInt(chunkOff + hs + 4);
        int attrStart = b.getShort(chunkOff + hs + 8) & 0xffff;
        int attrSize = b.getShort(chunkOff + hs + 10) & 0xffff;
        int attrCount = b.getShort(chunkOff + hs + 12) & 0xffff;
        if (attrSize == 0) attrSize = 20;
        pad();
        out.append('<').append(s(name));
        int attrBase = chunkOff + hs + attrStart;
        for (int i = 0; i < attrCount; i++) {
            int a = attrBase + i * attrSize;
            if (a + 20 > b.limit()) break;
            int aNs = b.getInt(a);
            int aName = b.getInt(a + 4);
            int raw = b.getInt(a + 8);
            int dt = b.get(a + 15) & 0xff;
            int ddata = b.getInt(a + 16);
            String prefix = nsIsAndroid(aNs) ? "android:" : "";
            String val = (raw != -1) ? esc(s(raw)) : esc(typedValue(dt, ddata));
            out.append(' ').append(prefix).append(s(aName)).append("=\"").append(val).append("\"");
        }
        out.append(">\n");
        indent++;
    }

    private void parseEnd(int chunkOff, int hs) {
        indent = Math.max(0, indent - 1);
        int name = b.getInt(chunkOff + hs + 4);
        pad();
        out.append("</").append(s(name)).append(">\n");
    }

    private void pad() { for (int i = 0; i < indent; i++) out.append("  "); }

    private boolean nsIsAndroid(int ns) {
        if (pool == null || ns < 0 || ns >= pool.length) return false;
        String u = pool[ns];
        return u != null && u.contains("schemas.android.com");
    }

    private String typedValue(int dt, int data) {
        switch (dt) {
            case 0x03: return s(data);
            case 0x01: return "@" + Integer.toHexString(data);
            case 0x10: return Integer.toString(data);
            case 0x11: return "0x" + Integer.toHexString(data);
            case 0x12: return data != 0 ? "true" : "false";
            case 0x04: return Float.toString(Float.intBitsToFloat(data));
            default: return "0x" + Integer.toHexString(data);
        }
    }

    private String s(int idx) {
        if (pool == null || idx < 0 || idx >= pool.length) return "";
        String v = pool[idx];
        return v == null ? "" : v;
    }

    private static String esc(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;");
    }
}
