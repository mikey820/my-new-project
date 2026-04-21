package com.mitmpatcher.app;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Injects android:networkSecurityConfig into a binary-encoded AndroidManifest.xml.
 * Handles both: app already has the attribute (updates value) and missing (adds it).
 */
public class BinaryXmlEditor {

    private static final int TYPE_STRING_POOL   = 0x0001;
    private static final int TYPE_RES_IDS       = 0x0180;
    private static final int TYPE_START_ELEM    = 0x0102;
    private static final int FLAG_UTF8          = 0x100;

    // android:networkSecurityConfig resource ID in the platform framework
    static final int RES_ID_NET_SEC_CFG = 0x0101054b;
    private static final String ANDROID_NS_URI =
            "http://schemas.android.com/apk/res/android";

    // -----------------------------------------------------------------------
    // Public entry point
    // -----------------------------------------------------------------------

    public static byte[] patch(byte[] manifest, int xmlResId) throws IOException {
        ByteBuffer buf = ByteBuffer.wrap(manifest).order(ByteOrder.LITTLE_ENDIAN);

        // File header: type(2) headerSize(2) fileSize(4)
        buf.getShort(); // file type 0x0003
        buf.getShort(); // headerSize = 8
        buf.getInt();   // fileSize (will be rewritten)

        // ---- String pool ----
        int spOffset = buf.position();
        buf.getShort(); // type 0x0001
        buf.getShort(); // headerSize = 28
        int spChunkSize = buf.getInt();
        int stringCount = buf.getInt();
        buf.getInt(); // styleCount
        int spFlags    = buf.getInt();
        int stringsStart = buf.getInt();
        buf.getInt(); // stylesStart
        boolean utf8 = (spFlags & FLAG_UTF8) != 0;

        int[] offsets = new int[stringCount];
        for (int i = 0; i < stringCount; i++) offsets[i] = buf.getInt();

        List<String> strings = new ArrayList<>();
        int strDataStart = spOffset + 28 + stringCount * 4; // after header + offsets
        for (int i = 0; i < stringCount; i++) {
            buf.position(strDataStart + offsets[i]);
            strings.add(utf8 ? readUtf8String(buf) : readUtf16String(buf));
        }
        buf.position(spOffset + spChunkSize);

        // ---- Resource IDs ----
        int resIdsOffset = buf.position();
        List<Integer> resIds = new ArrayList<>();
        if (buf.remaining() >= 4) {
            int mark = buf.position();
            int chType = buf.getShort() & 0xFFFF;
            buf.getShort(); // headerSize
            int chSize = buf.getInt();
            if (chType == TYPE_RES_IDS) {
                int count = (chSize - 8) / 4;
                for (int i = 0; i < count; i++) resIds.add(buf.getInt());
            } else {
                buf.position(mark); // not a res-ids chunk, reset
            }
        }
        int xmlNodesStart = buf.position();
        byte[] xmlNodes = new byte[manifest.length - xmlNodesStart];
        System.arraycopy(manifest, xmlNodesStart, xmlNodes, 0, xmlNodes.length);

        // ---- Ensure android NS URI is in string pool ----
        int nsIdx = findString(strings, ANDROID_NS_URI);
        if (nsIdx < 0) {
            strings.add(ANDROID_NS_URI);
            nsIdx = strings.size() - 1;
        }

        // ---- Ensure "networkSecurityConfig" is in string pool ----
        int nameIdx = findString(strings, "networkSecurityConfig");
        if (nameIdx < 0) {
            strings.add("networkSecurityConfig");
            nameIdx = strings.size() - 1;
        }

        // ---- Extend resource IDs to cover nameIdx, set it to RES_ID_NET_SEC_CFG ----
        while (resIds.size() <= nameIdx) resIds.add(0);
        resIds.set(nameIdx, RES_ID_NET_SEC_CFG);

        // ---- Patch XML nodes: find <application> and inject/update attribute ----
        byte[] patchedNodes = patchApplicationElement(xmlNodes, strings, resIds, nameIdx, nsIdx, xmlResId);

        // ---- Serialize ----
        byte[] newSP  = serializeStringPool(strings, utf8, spFlags);
        byte[] newRID = serializeResIds(resIds);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // File header
        writeShortLE(out, 0x0003);
        writeShortLE(out, 8);
        int newFileSize = 8 + newSP.length + newRID.length + patchedNodes.length;
        writeIntLE(out, newFileSize);
        out.write(newSP);
        out.write(newRID);
        out.write(patchedNodes);
        return out.toByteArray();
    }

    // -----------------------------------------------------------------------
    // Patch the XML nodes section
    // -----------------------------------------------------------------------

    private static byte[] patchApplicationElement(byte[] nodes, List<String> strings,
            List<Integer> resIds, int nameIdx, int nsIdx, int xmlResId) throws IOException {

        int appNameIdx = findString(strings, "application");
        ByteBuffer in = ByteBuffer.wrap(nodes).order(ByteOrder.LITTLE_ENDIAN);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        while (in.remaining() >= 8) {
            int chunkStart = in.position();
            int type       = in.getShort() & 0xFFFF;
            int headerSize = in.getShort() & 0xFFFF;
            int chunkSize  = in.getInt();

            if (chunkSize < 8 || chunkSize > in.capacity() - chunkStart) break;

            byte[] chunk = new byte[chunkSize];
            System.arraycopy(nodes, chunkStart, chunk, 0, chunkSize);

            if (type == TYPE_START_ELEM && chunkSize >= 36) {
                ByteBuffer cb = ByteBuffer.wrap(chunk).order(ByteOrder.LITTLE_ENDIAN);
                cb.position(8);  // skip chunk header
                cb.getInt();     // lineNumber
                cb.getInt();     // comment
                cb.getInt();     // ns
                int elemName = cb.getInt();

                if (elemName == appNameIdx) {
                    chunk = patchAppElem(chunk, resIds, nameIdx, nsIdx, xmlResId);
                }
            }

            out.write(chunk);
            in.position(chunkStart + chunkSize);
        }
        return out.toByteArray();
    }

    private static byte[] patchAppElem(byte[] chunk, List<Integer> resIds,
            int nameIdx, int nsIdx, int xmlResId) {

        ByteBuffer cb = ByteBuffer.wrap(chunk).order(ByteOrder.LITTLE_ENDIAN);
        // attrCount is at offset 28 (2 bytes)
        cb.position(28);
        int attrCount = cb.getShort() & 0xFFFF;

        // Scan attrs (each 20 bytes starting at offset 36)
        int attrBase = 36;
        for (int i = 0; i < attrCount; i++) {
            int off = attrBase + i * 20;
            cb.position(off + 4); // skip ns, point to name
            int attrName = cb.getInt();
            int rid = (attrName >= 0 && attrName < resIds.size()) ? resIds.get(attrName) : 0;
            if (rid == BinaryXmlEditor.RES_ID_NET_SEC_CFG) {
                // Already present — update value
                cb.position(off + 16); // dataType + data
                cb.put((byte) 0);      // size hi
                cb.put((byte) 8);      // size lo (little-endian 16-bit → 8,0 written as bytes)
                // Actually Res_value: size(2) res0(1) dataType(1) data(4)
                cb.position(off + 12);
                cb.putShort((short) 8);   // size
                cb.put((byte) 0);         // res0
                cb.put((byte) 0x01);      // TYPE_REFERENCE
                cb.putInt(xmlResId);
                return chunk;
            }
        }

        // Not found — append new 20-byte attribute and grow chunk
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(chunk, 0, chunk.length);

        // Build the attribute: ns(4) name(4) rawValue(4) resValue_size(2) res0(1) dataType(1) data(4)
        ByteBuffer attr = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN);
        attr.putInt(nsIdx);
        attr.putInt(nameIdx);
        attr.putInt(-1);        // rawValue = -1 (none)
        attr.putShort((short) 8);  // Res_value.size
        attr.put((byte) 0);        // Res_value.res0
        attr.put((byte) 0x01);     // TYPE_REFERENCE
        attr.putInt(xmlResId);
        try { out.write(attr.array()); } catch (IOException ignored) {}

        byte[] result = out.toByteArray();
        // Update attrCount (+1) at offset 28
        ByteBuffer rb = ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN);
        rb.position(28);
        rb.putShort((short)(attrCount + 1));
        // Update chunkSize at offset 4
        rb.position(4);
        rb.putInt(result.length);
        return result;
    }

    // -----------------------------------------------------------------------
    // String pool serialization
    // -----------------------------------------------------------------------

    private static byte[] serializeStringPool(List<String> strings, boolean utf8, int origFlags) throws IOException {
        int flags = origFlags;
        if (utf8) flags |= FLAG_UTF8; else flags &= ~FLAG_UTF8;
        flags &= ~0x200; // clear sorted flag

        ByteArrayOutputStream strData = new ByteArrayOutputStream();
        int[] offsets = new int[strings.size()];

        for (int i = 0; i < strings.size(); i++) {
            offsets[i] = strData.size();
            if (utf8) writeUtf8String(strData, strings.get(i));
            else      writeUtf16String(strData, strings.get(i));
        }

        // Pad strData to 4-byte boundary
        while (strData.size() % 4 != 0) strData.write(0);

        int headerSize  = 28;
        int offsetBytes = strings.size() * 4;
        int stringsStart = headerSize + offsetBytes;
        int chunkSize   = stringsStart + strData.size();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeShortLE(out, TYPE_STRING_POOL);
        writeShortLE(out, headerSize);
        writeIntLE(out, chunkSize);
        writeIntLE(out, strings.size());
        writeIntLE(out, 0); // styleCount
        writeIntLE(out, flags);
        writeIntLE(out, stringsStart);
        writeIntLE(out, 0); // stylesStart
        for (int off : offsets) writeIntLE(out, off);
        out.write(strData.toByteArray());
        return out.toByteArray();
    }

    private static byte[] serializeResIds(List<Integer> resIds) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int chunkSize = 8 + resIds.size() * 4;
        writeShortLE(out, TYPE_RES_IDS);
        writeShortLE(out, 8);
        writeIntLE(out, chunkSize);
        for (int id : resIds) writeIntLE(out, id);
        return out.toByteArray();
    }

    // -----------------------------------------------------------------------
    // String encoding helpers
    // -----------------------------------------------------------------------

    private static String readUtf8String(ByteBuffer buf) {
        int charLen = buf.get() & 0xFF;
        if ((charLen & 0x80) != 0) charLen = ((charLen & 0x7F) << 8) | (buf.get() & 0xFF);
        int byteLen = buf.get() & 0xFF;
        if ((byteLen & 0x80) != 0) byteLen = ((byteLen & 0x7F) << 8) | (buf.get() & 0xFF);
        byte[] bytes = new byte[byteLen];
        buf.get(bytes);
        buf.get(); // null terminator
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static String readUtf16String(ByteBuffer buf) {
        int charLen = buf.getShort() & 0xFFFF;
        if ((charLen & 0x8000) != 0) charLen = ((charLen & 0x7FFF) << 16) | (buf.getShort() & 0xFFFF);
        byte[] bytes = new byte[charLen * 2];
        buf.get(bytes);
        buf.getShort(); // null terminator
        return new String(bytes, StandardCharsets.UTF_16LE);
    }

    private static void writeUtf8String(ByteArrayOutputStream out, String s) throws IOException {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        int charLen = s.length();
        int byteLen = bytes.length;
        if (charLen > 0x7F) { out.write((charLen >> 8) | 0x80); out.write(charLen & 0xFF); }
        else out.write(charLen);
        if (byteLen > 0x7F) { out.write((byteLen >> 8) | 0x80); out.write(byteLen & 0xFF); }
        else out.write(byteLen);
        out.write(bytes);
        out.write(0); // null
    }

    private static void writeUtf16String(ByteArrayOutputStream out, String s) throws IOException {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_16LE);
        int charLen = s.length();
        if (charLen > 0x7FFF) { writeShortLE(out, (charLen >> 16) | 0x8000); writeShortLE(out, charLen & 0xFFFF); }
        else writeShortLE(out, charLen);
        out.write(bytes);
        writeShortLE(out, 0); // null
    }

    // -----------------------------------------------------------------------
    // Tiny LE write helpers
    // -----------------------------------------------------------------------

    private static void writeShortLE(ByteArrayOutputStream out, int v) {
        out.write(v & 0xFF);
        out.write((v >> 8) & 0xFF);
    }

    private static void writeIntLE(ByteArrayOutputStream out, int v) {
        out.write(v & 0xFF);
        out.write((v >> 8) & 0xFF);
        out.write((v >> 16) & 0xFF);
        out.write((v >> 24) & 0xFF);
    }

    private static int findString(List<String> strings, String target) {
        for (int i = 0; i < strings.size(); i++) {
            if (target.equals(strings.get(i))) return i;
        }
        return -1;
    }
}
