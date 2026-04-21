package com.mitmpatcher.app;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Adds (or finds) a "network_security_config" entry in the xml resource type.
 * Returns the resource ID to use for the manifest attribute.
 *
 * Strategy:
 *  1. Check if an entry named "network_security_config" already exists → reuse its ID
 *  2. Otherwise, find the "xml" type and append a new entry
 */
public class ResourcesArscEditor {

    public static final class Result {
        public final byte[] patchedArsc; // null if no patching needed
        public final int resourceId;
        Result(byte[] a, int id) { patchedArsc = a; resourceId = id; }
    }

    private static final int RES_TABLE_TYPE         = 0x0002;
    private static final int RES_STRING_POOL_TYPE   = 0x0001;
    private static final int RES_TABLE_PACKAGE_TYPE = 0x0200;
    private static final int RES_TABLE_TYPE_TYPE    = 0x0201;
    private static final int RES_TABLE_TYPESPEC_TYPE= 0x0202;
    private static final int NO_ENTRY               = 0xFFFFFFFF;

    public static Result process(byte[] arsc) throws IOException {
        ByteBuffer buf = ByteBuffer.wrap(arsc).order(ByteOrder.LITTLE_ENDIAN);

        // ResTable header
        buf.getShort(); // type
        buf.getShort(); // headerSize
        buf.getInt();   // fileSize
        buf.getInt();   // packageCount

        // Global string pool
        int gspOffset = buf.position();
        buf.getShort(); // type
        buf.getShort(); // headerSize = 28
        int gspSize = buf.getInt();
        int gspStringCount = buf.getInt();
        buf.getInt(); // styleCount
        int gspFlags = buf.getInt();
        int gspStringsStart = buf.getInt();
        buf.getInt(); // stylesStart

        boolean gspUtf8 = (gspFlags & 0x100) != 0;
        int[] gspOffsets = new int[gspStringCount];
        for (int i = 0; i < gspStringCount; i++) gspOffsets[i] = buf.getInt();

        List<String> globalStrings = new ArrayList<>();
        for (int i = 0; i < gspStringCount; i++) {
            buf.position(gspOffset + gspStringsStart + gspOffsets[i]);
            globalStrings.add(gspUtf8 ? readUtf8(buf) : readUtf16(buf));
        }
        buf.position(gspOffset + gspSize);

        // Package chunk
        int pkgOffset = buf.position();
        buf.getShort(); // type
        int pkgHeaderSize = buf.getShort() & 0xFFFF;
        int pkgChunkSize  = buf.getInt();
        int packageId     = buf.getInt();
        buf.position(pkgOffset + 8 + 4 + 256); // skip id + name[128 chars UTF-16]
        buf.getInt(); // typeStrings offset
        buf.getInt(); // lastPublicType
        buf.getInt(); // keyStrings offset
        buf.getInt(); // lastPublicKey
        buf.getInt(); // typeIdOffset

        // Type strings pool (inside package)
        int typeSpOffset = pkgOffset + pkgHeaderSize;
        buf.position(typeSpOffset);
        buf.getShort(); buf.getShort();
        int typeSpSize = buf.getInt();
        int typeSpStrCount = buf.getInt();
        buf.getInt(); buf.getInt();
        int typeSpStringsStart = buf.getInt();
        buf.getInt();
        int[] typeSpOffsets = new int[typeSpStrCount];
        for (int i = 0; i < typeSpStrCount; i++) typeSpOffsets[i] = buf.getInt();

        List<String> typeNames = new ArrayList<>();
        for (int i = 0; i < typeSpStrCount; i++) {
            buf.position(typeSpOffset + typeSpStringsStart + typeSpOffsets[i]);
            typeNames.add(readUtf8OrUtf16(buf, gspUtf8));
        }
        buf.position(typeSpOffset + typeSpSize);

        // Key strings pool
        int keySpOffset = buf.position();
        buf.getShort(); buf.getShort();
        int keySpSize = buf.getInt();
        int keySpStrCount = buf.getInt();
        buf.getInt(); buf.getInt();
        int keySpStringsStart = buf.getInt();
        buf.getInt();
        int[] keySpOffsets = new int[keySpStrCount];
        for (int i = 0; i < keySpStrCount; i++) keySpOffsets[i] = buf.getInt();

        List<String> keyNames = new ArrayList<>();
        for (int i = 0; i < keySpStrCount; i++) {
            buf.position(keySpOffset + keySpStringsStart + keySpOffsets[i]);
            keyNames.add(readUtf8OrUtf16(buf, gspUtf8));
        }
        buf.position(keySpOffset + keySpSize);

        // Find "xml" type index (0-based in typeNames → 1-based typeId in resource IDs)
        int xmlTypeIdx = findString(typeNames, "xml");
        if (xmlTypeIdx < 0) {
            // App has no xml resource type at all — create one from scratch
            return createXmlTypeAndEntry(arsc, gspOffset, gspSize, globalStrings, gspUtf8, gspFlags,
                    pkgOffset, pkgChunkSize, pkgHeaderSize, typeNames, keyNames, packageId);
        }
        int xmlTypeId = xmlTypeIdx + 1; // 1-based

        // Check if "network_security_config" key already exists
        int nscKeyIdx = findString(keyNames, "network_security_config");
        if (nscKeyIdx >= 0) {
            // Key exists — find its entry in any xml ResTable_type chunk
            int existingResId = findExistingEntry(buf, pkgOffset, pkgChunkSize,
                    xmlTypeId, nscKeyIdx, packageId);
            if (existingResId != 0) {
                return new Result(null, existingResId);
            }
        }

        // Need to add the entry. Find xml ResTable_typeSpec and ResTable_type chunks.
        // We'll do a full rebuild of the package chunk.
        return addXmlEntry(arsc, gspOffset, gspSize, globalStrings, gspUtf8, gspFlags,
                pkgOffset, pkgChunkSize, typeNames, keyNames, xmlTypeId, packageId);
    }

    // -----------------------------------------------------------------------
    // Scan for existing entry
    // -----------------------------------------------------------------------

    private static int findExistingEntry(ByteBuffer buf, int pkgOffset, int pkgChunkSize,
            int xmlTypeId, int keyIdx, int packageId) {
        int pos = pkgOffset;
        int pkgEnd = pkgOffset + pkgChunkSize;
        // We need to restart scanning from pkgOffset after the two string pools
        // For simplicity, scan by re-reading the buffer
        buf = buf.duplicate().order(ByteOrder.LITTLE_ENDIAN);
        buf.position(pos + 8); // skip package header type+headerSize+chunkSize
        buf.position(pkgOffset);
        buf.getShort(); buf.getShort(); buf.getInt(); // package header
        // skip to after key strings pool
        // (already done above — we call this after key strings, so use remaining pkg data)
        while (buf.position() < pkgEnd - 8) {
            int chStart = buf.position();
            int ct = buf.getShort() & 0xFFFF;
            buf.getShort();
            if (buf.remaining() < 4) break;
            int cs = buf.getInt();
            if (cs < 8) break;
            if (ct == RES_TABLE_TYPE_TYPE) {
                int tid = buf.get() & 0xFF;
                if (tid == xmlTypeId) {
                    buf.get(); buf.getShort(); // flags, reserved
                    int entryCount = buf.getInt();
                    int entriesStart = buf.getInt();
                    buf.position(chStart + 52); // skip ResTable_config (36 bytes) + header
                    for (int e = 0; e < entryCount; e++) {
                        int offset = buf.getInt();
                        if (offset == NO_ENTRY) continue;
                        int entryPos = chStart + entriesStart + offset;
                        ByteBuffer eb = buf.duplicate().order(ByteOrder.LITTLE_ENDIAN);
                        eb.position(entryPos + 2); // skip size
                        eb.getShort(); // flags
                        int ek = eb.getInt(); // key string index
                        if (ek == keyIdx) {
                            return (packageId << 24) | (xmlTypeId << 16) | e;
                        }
                    }
                }
            }
            buf.position(chStart + cs);
        }
        return 0;
    }

    // -----------------------------------------------------------------------
    // Add new xml entry
    // -----------------------------------------------------------------------

    private static Result addXmlEntry(byte[] arsc,
            int gspOffset, int gspSize, List<String> globalStrings, boolean utf8, int gspFlags,
            int pkgOffset, int pkgChunkSize,
            List<String> typeNames, List<String> keyNames,
            int xmlTypeId, int packageId) throws IOException {

        String filePath = "res/xml/network_security_config.xml";
        int filePathIdx = findString(globalStrings, filePath);
        if (filePathIdx < 0) {
            globalStrings.add(filePath);
            filePathIdx = globalStrings.size() - 1;
        }

        keyNames.add("network_security_config");
        int newKeyIdx = keyNames.size() - 1;

        // Rebuild global string pool
        byte[] newGsp = serializeStringPool(globalStrings, utf8, gspFlags);

        // Rebuild package chunk
        byte[] origPkg = new byte[pkgChunkSize];
        System.arraycopy(arsc, pkgOffset, origPkg, 0, pkgChunkSize);
        byte[] newPkg = rebuildPackage(origPkg, typeNames, keyNames, utf8,
                xmlTypeId, newKeyIdx, filePathIdx, packageId);

        // Assemble
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // ResTable header
        writeShortLE(out, RES_TABLE_TYPE);
        writeShortLE(out, 12);
        int newFileSize = 12 + newGsp.length + newPkg.length;
        writeIntLE(out, newFileSize);
        writeIntLE(out, 1); // packageCount
        out.write(newGsp);
        out.write(newPkg);

        int entryIdx = countXmlEntries(origPkg, xmlTypeId); // next entry index
        int newResId = (packageId << 24) | (xmlTypeId << 16) | entryIdx;
        return new Result(out.toByteArray(), newResId);
    }

    private static byte[] rebuildPackage(byte[] origPkg,
            List<String> typeNames, List<String> keyNames, boolean utf8,
            int xmlTypeId, int newKeyIdx, int filePathIdx, int packageId) throws IOException {

        ByteBuffer buf = ByteBuffer.wrap(origPkg).order(ByteOrder.LITTLE_ENDIAN);
        // Skip package header (not re-written here, recalculate size later)
        buf.getShort(); buf.getShort(); buf.getInt(); // type, headerSize, chunkSize
        buf.getInt(); // packageId
        byte[] pkgName = new byte[256]; buf.get(pkgName);
        buf.getInt(); buf.getInt(); buf.getInt(); buf.getInt(); buf.getInt(); // offsets

        int pkgHeaderSize = 288; // standard ResTable_package header

        // Build new type strings pool
        byte[] newTSP = serializeStringPool(typeNames, utf8, utf8 ? 0x100 : 0);
        // Build new key strings pool
        byte[] newKSP = serializeStringPool(keyNames, utf8, utf8 ? 0x100 : 0);

        // Copy the rest of the package (typeSpec + type chunks), patching xml type
        buf.position(pkgHeaderSize);
        // Skip old type strings + key strings
        buf.getShort(); buf.getShort(); int oldTSPSize = buf.getInt(); buf.position(buf.position() - 8 + oldTSPSize);
        buf.getShort(); buf.getShort(); int oldKSPSize = buf.getInt(); buf.position(buf.position() - 8 + oldKSPSize);

        ByteArrayOutputStream rest = new ByteArrayOutputStream();
        // Patch typeSpec and type chunks for xmlTypeId
        while (buf.remaining() >= 8) {
            int chStart = buf.position();
            int ct = buf.getShort() & 0xFFFF;
            buf.getShort();
            int cs = buf.getInt();
            if (cs < 8 || cs > buf.capacity() - chStart) break;

            byte[] chunk = new byte[cs];
            System.arraycopy(origPkg, chStart, chunk, 0, cs);

            if (ct == RES_TABLE_TYPESPEC_TYPE) {
                int tid = origPkg[chStart + 8] & 0xFF;
                if (tid == xmlTypeId) chunk = patchTypeSpec(chunk);
            } else if (ct == RES_TABLE_TYPE_TYPE) {
                int tid = origPkg[chStart + 8] & 0xFF;
                if (tid == xmlTypeId) chunk = patchTypeChunk(chunk, newKeyIdx, filePathIdx);
            }

            rest.write(chunk);
            buf.position(chStart + cs);
        }

        // Assemble package
        ByteArrayOutputStream pkg = new ByteArrayOutputStream();
        writeShortLE(pkg, RES_TABLE_PACKAGE_TYPE);
        writeShortLE(pkg, pkgHeaderSize);
        // chunkSize placeholder
        int tspRelOffset = pkgHeaderSize;
        int kspRelOffset = tspRelOffset + newTSP.length;
        int dataOffset   = kspRelOffset + newKSP.length;
        writeIntLE(pkg, pkgHeaderSize + newTSP.length + newKSP.length + rest.size()); // chunkSize
        writeIntLE(pkg, packageId & 0x7f);
        pkg.write(pkgName);
        writeIntLE(pkg, tspRelOffset);
        writeIntLE(pkg, typeNames.size());
        writeIntLE(pkg, kspRelOffset);
        writeIntLE(pkg, keyNames.size());
        writeIntLE(pkg, 0); // typeIdOffset
        pkg.write(newTSP);
        pkg.write(newKSP);
        pkg.write(rest.toByteArray());
        return pkg.toByteArray();
    }

    private static byte[] patchTypeSpec(byte[] chunk) throws IOException {
        ByteBuffer buf = ByteBuffer.wrap(chunk).order(ByteOrder.LITTLE_ENDIAN);
        buf.getShort(); buf.getShort(); buf.getInt();
        buf.get(); buf.get(); buf.getShort(); // id, res0, res1 (unused)
        int entryCount = buf.getInt();
        // Append one more specFlags entry (0 = no special flags)
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(chunk);
        writeIntLE(out, 0);
        byte[] result = out.toByteArray();
        // Update chunkSize and entryCount
        ByteBuffer rb = ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN);
        rb.position(4); rb.putInt(result.length);
        rb.position(12); rb.putInt(entryCount + 1);
        return result;
    }

    private static byte[] patchTypeChunk(byte[] chunk, int keyIdx, int filePathStrIdx) throws IOException {
        ByteBuffer buf = ByteBuffer.wrap(chunk).order(ByteOrder.LITTLE_ENDIAN);
        buf.getShort(); buf.getShort(); buf.getInt(); // header
        buf.get(); buf.get(); buf.getShort(); // id, flags, reserved
        int entryCount  = buf.getInt();
        int entriesStart = buf.getInt();
        // entriesStart is relative to chunk start; resize header to accommodate new offset
        // New offset array entry for our new entry (value = 0, meaning first position after existing)
        // Simple approach: append NO_ENTRY for all existing, new entry at back

        // Compute existing entry data size (from entriesStart to end of chunk)
        int entryDataSize = chunk.length - entriesStart;

        // New entry data: ResTable_entry (8 bytes) + Res_value (8 bytes)
        ByteArrayOutputStream newEntry = new ByteArrayOutputStream();
        writeShortLE(newEntry, 8);   // entry size
        writeShortLE(newEntry, 0);   // flags (simple)
        writeIntLE(newEntry, keyIdx); // key string index
        // Res_value: size(2) res0(1) dataType(1) data(4)
        writeShortLE(newEntry, 8);
        newEntry.write(0);
        newEntry.write(0x03); // TYPE_STRING
        writeIntLE(newEntry, filePathStrIdx);
        byte[] newEntryBytes = newEntry.toByteArray();

        // New offset = entryDataSize (appended at end)
        int newOffset = entryDataSize;

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // Write header up through entriesStart field
        out.write(chunk, 0, 20); // type(2)+hdrSz(2)+chunkSz(4)+id(1)+flags(1)+res(2)+entryCount(4)+entriesStart(4)=20
        // Write existing offsets (4 bytes each)
        for (int i = 0; i < entryCount; i++) {
            buf.position(52 + i * 4); // 52 = 20 + ResTable_config (36 bytes) - wait this isn't right
        }
        // Easier: copy offsets block directly
        int configSize  = 36; // ResTable_config size for most cases
        int offsetsStart = 20 + configSize; // = 56 from chunk start

        // But entriesStart gives us the offset to entry data from chunk start
        // offsetsBlock runs from offsetsStart to entriesStart
        out.write(chunk, 0, entriesStart); // everything up to entry data
        // Append offset for new entry
        ByteBuffer ob = ByteBuffer.wrap(out.toByteArray()).order(ByteOrder.LITTLE_ENDIAN);
        // We already wrote this — now append newOffset as int at the end of offset array
        // Actually we need to insert it BEFORE the entry data
        // Re-do: write header + offsets + new offset + existing entry data + new entry data
        ByteArrayOutputStream final_ = new ByteArrayOutputStream();
        final_.write(chunk, 0, entriesStart);    // header + config + existing offsets
        writeIntLE(final_, newOffset);           // new entry's offset
        final_.write(chunk, entriesStart, entryDataSize); // existing entries
        final_.write(newEntryBytes);             // new entry

        byte[] result = final_.toByteArray();
        // Update: chunkSize, entryCount, entriesStart (+4 for the new offset)
        ByteBuffer rb = ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN);
        rb.position(4);  rb.putInt(result.length);
        rb.position(12); rb.putInt(entryCount + 1);
        rb.position(16); rb.putInt(entriesStart + 4); // entriesStart shifts by one int
        return result;
    }

    // -----------------------------------------------------------------------
    // Count existing xml entries to get next entry index
    // -----------------------------------------------------------------------

    private static int countXmlEntries(byte[] pkg, int xmlTypeId) {
        ByteBuffer buf = ByteBuffer.wrap(pkg).order(ByteOrder.LITTLE_ENDIAN);
        buf.position(288); // skip package header
        // skip type strings + key strings
        buf.getShort(); buf.getShort(); int s = buf.getInt(); buf.position(buf.position() - 8 + s);
        buf.getShort(); buf.getShort(); s = buf.getInt(); buf.position(buf.position() - 8 + s);
        while (buf.remaining() >= 8) {
            int cs = buf.position();
            int ct = buf.getShort() & 0xFFFF;
            buf.getShort();
            int sz = buf.getInt();
            if (sz < 8) break;
            if (ct == RES_TABLE_TYPE_TYPE) {
                int tid = buf.get() & 0xFF;
                if (tid == xmlTypeId) {
                    buf.get(); buf.getShort();
                    return buf.getInt(); // entryCount
                }
            }
            buf.position(cs + sz);
        }
        return 0;
    }

    // -----------------------------------------------------------------------
    // Create a brand-new "xml" resource type when the app has none
    // -----------------------------------------------------------------------

    private static Result createXmlTypeAndEntry(byte[] arsc,
            int gspOffset, int gspSize, List<String> globalStrings, boolean utf8, int gspFlags,
            int pkgOffset, int pkgChunkSize, int pkgHeaderSize,
            List<String> typeNames, List<String> keyNames, int packageId) throws IOException {

        // Add file path to global string pool
        String filePath = "res/xml/network_security_config.xml";
        int filePathIdx = findString(globalStrings, filePath);
        if (filePathIdx < 0) {
            globalStrings.add(filePath);
            filePathIdx = globalStrings.size() - 1;
        }

        // Add "xml" type and "network_security_config" key
        typeNames.add("xml");
        int newTypeId = typeNames.size(); // 1-indexed
        keyNames.add("network_security_config");
        int newKeyIdx = keyNames.size() - 1;

        byte[] newGsp      = serializeStringPool(globalStrings, utf8, gspFlags);
        byte[] newTSP      = serializeStringPool(typeNames, utf8, utf8 ? 0x100 : 0);
        byte[] newKSP      = serializeStringPool(keyNames,  utf8, utf8 ? 0x100 : 0);
        byte[] newTypeSpec = buildNewTypeSpec(newTypeId);
        byte[] newTypeChk  = buildNewTypeChunk(newTypeId, newKeyIdx, filePathIdx);

        // Read original package to extract name and existing type data
        ByteBuffer pbuf = ByteBuffer.wrap(arsc, pkgOffset, pkgChunkSize).order(ByteOrder.LITTLE_ENDIAN);
        pbuf.getShort(); pbuf.getShort(); pbuf.getInt(); // chunk header
        pbuf.getInt();                                   // packageId
        byte[] pkgName = new byte[256]; pbuf.get(pkgName);
        pbuf.getInt(); pbuf.getInt(); pbuf.getInt(); pbuf.getInt(); pbuf.getInt(); // field offsets

        // Skip old typeStrings + keyStrings pools
        int tspStart = pkgHeaderSize;
        pbuf.position(tspStart);
        pbuf.getShort(); pbuf.getShort(); int oldTspSize = pbuf.getInt();
        pbuf.position(tspStart + oldTspSize);
        pbuf.getShort(); pbuf.getShort(); int oldKspSize = pbuf.getInt();
        int existingDataStart = tspStart + oldTspSize + oldKspSize;
        int existingDataLen   = pkgChunkSize - existingDataStart;
        byte[] existingData = new byte[existingDataLen];
        System.arraycopy(arsc, pkgOffset + existingDataStart, existingData, 0, existingDataLen);

        // Build new package chunk
        int newPkgSize = pkgHeaderSize + newTSP.length + newKSP.length
                + existingDataLen + newTypeSpec.length + newTypeChk.length;
        ByteArrayOutputStream pkg = new ByteArrayOutputStream();
        writeShortLE(pkg, RES_TABLE_PACKAGE_TYPE);
        writeShortLE(pkg, pkgHeaderSize);
        writeIntLE(pkg, newPkgSize);
        writeIntLE(pkg, packageId & 0x7f);
        pkg.write(pkgName);
        writeIntLE(pkg, pkgHeaderSize);                       // typeStrings offset
        writeIntLE(pkg, newTypeId);                           // lastPublicType
        writeIntLE(pkg, pkgHeaderSize + newTSP.length);       // keyStrings offset
        writeIntLE(pkg, newKeyIdx);                           // lastPublicKey
        writeIntLE(pkg, 0);                                   // typeIdOffset
        pkg.write(newTSP);
        pkg.write(newKSP);
        pkg.write(existingData);
        pkg.write(newTypeSpec);
        pkg.write(newTypeChk);

        // Assemble full resources.arsc
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeShortLE(out, RES_TABLE_TYPE);
        writeShortLE(out, 12);
        writeIntLE(out, 12 + newGsp.length + newPkgSize);
        writeIntLE(out, 1); // packageCount
        out.write(newGsp);
        out.write(pkg.toByteArray());

        int newResId = (packageId << 24) | (newTypeId << 16) | 0;
        return new Result(out.toByteArray(), newResId);
    }

    /** ResTable_typeSpec for a single-entry type. */
    private static byte[] buildNewTypeSpec(int typeId) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeShortLE(out, RES_TABLE_TYPESPEC_TYPE); // 0x0202
        writeShortLE(out, 16);   // headerSize = sizeof(ResTable_typeSpec)
        writeIntLE(out, 20);     // chunkSize = 16 + 1*4
        out.write(typeId & 0xFF);
        out.write(0);            // res0
        writeShortLE(out, 0);    // res1
        writeIntLE(out, 1);      // entryCount
        writeIntLE(out, 0);      // specFlags[0] = 0
        return out.toByteArray();
    }

    /** ResTable_type with one entry pointing to a string (file path) in the global pool. */
    private static byte[] buildNewTypeChunk(int typeId, int keyIdx, int filePathStrIdx)
            throws IOException {
        // ResTable_config: 48 bytes (all zeros = default/any config, with size=48)
        int configSize = 48;
        // headerSize = ResChunk_header(8) + id(1)+flags(1)+reserved(2) + entryCount(4)
        //            + entriesStart(4) + config(configSize) = 20 + configSize
        int headerSize   = 20 + configSize; // = 68
        int entryCount   = 1;
        int entriesStart = headerSize + entryCount * 4; // 68 + 4 = 72
        // Entry = ResTable_entry(8) + Res_value(8) = 16 bytes
        int chunkSize = entriesStart + 16;

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeShortLE(out, RES_TABLE_TYPE_TYPE); // 0x0201
        writeShortLE(out, headerSize);
        writeIntLE(out, chunkSize);
        out.write(typeId & 0xFF);
        out.write(0);            // flags
        writeShortLE(out, 0);   // reserved
        writeIntLE(out, entryCount);
        writeIntLE(out, entriesStart);
        // ResTable_config (48 bytes)
        writeIntLE(out, configSize); // config.size
        for (int i = 0; i < configSize - 4; i++) out.write(0); // remaining config bytes
        // Offsets array: offset[0] = 0
        writeIntLE(out, 0);
        // ResTable_entry
        writeShortLE(out, 8);   // entry.size
        writeShortLE(out, 0);   // entry.flags (simple, not complex)
        writeIntLE(out, keyIdx);
        // Res_value
        writeShortLE(out, 8);   // value.size
        out.write(0);           // value.res0
        out.write(0x03);        // value.dataType = TYPE_STRING
        writeIntLE(out, filePathStrIdx);
        return out.toByteArray();
    }

    // -----------------------------------------------------------------------
    // String pool helpers
    // -----------------------------------------------------------------------

    private static byte[] serializeStringPool(List<String> strings, boolean utf8, int origFlags) throws IOException {
        int flags = origFlags;
        if (utf8) flags |= 0x100; else flags &= ~0x100;
        flags &= ~0x200;

        ByteArrayOutputStream strData = new ByteArrayOutputStream();
        int[] offsets = new int[strings.size()];
        for (int i = 0; i < strings.size(); i++) {
            offsets[i] = strData.size();
            if (utf8) writeUtf8Str(strData, strings.get(i));
            else      writeUtf16Str(strData, strings.get(i));
        }
        while (strData.size() % 4 != 0) strData.write(0);

        int headerSize   = 28;
        int offsetBytes  = strings.size() * 4;
        int stringsStart = headerSize + offsetBytes;
        int chunkSize    = stringsStart + strData.size();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeShortLE(out, RES_STRING_POOL_TYPE);
        writeShortLE(out, headerSize);
        writeIntLE(out, chunkSize);
        writeIntLE(out, strings.size());
        writeIntLE(out, 0);
        writeIntLE(out, flags);
        writeIntLE(out, stringsStart);
        writeIntLE(out, 0);
        for (int off : offsets) writeIntLE(out, off);
        out.write(strData.toByteArray());
        return out.toByteArray();
    }

    private static String readUtf8(ByteBuffer buf) {
        int cl = buf.get() & 0xFF;
        if ((cl & 0x80) != 0) cl = ((cl & 0x7F) << 8) | (buf.get() & 0xFF);
        int bl = buf.get() & 0xFF;
        if ((bl & 0x80) != 0) bl = ((bl & 0x7F) << 8) | (buf.get() & 0xFF);
        byte[] b = new byte[bl]; buf.get(b); buf.get();
        return new String(b, StandardCharsets.UTF_8);
    }

    private static String readUtf16(ByteBuffer buf) {
        int cl = buf.getShort() & 0xFFFF;
        if ((cl & 0x8000) != 0) cl = ((cl & 0x7FFF) << 16) | (buf.getShort() & 0xFFFF);
        byte[] b = new byte[cl * 2]; buf.get(b); buf.getShort();
        return new String(b, StandardCharsets.UTF_16LE);
    }

    private static String readUtf8OrUtf16(ByteBuffer buf, boolean utf8) {
        return utf8 ? readUtf8(buf) : readUtf16(buf);
    }

    private static void writeUtf8Str(ByteArrayOutputStream out, String s) throws IOException {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        int cl = s.length(), bl = b.length;
        if (cl > 0x7F) { out.write((cl >> 8) | 0x80); out.write(cl & 0xFF); } else out.write(cl);
        if (bl > 0x7F) { out.write((bl >> 8) | 0x80); out.write(bl & 0xFF); } else out.write(bl);
        out.write(b); out.write(0);
    }

    private static void writeUtf16Str(ByteArrayOutputStream out, String s) throws IOException {
        byte[] b = s.getBytes(StandardCharsets.UTF_16LE);
        int cl = s.length();
        if (cl > 0x7FFF) { writeShortLE(out, (cl >> 16) | 0x8000); writeShortLE(out, cl & 0xFFFF); }
        else writeShortLE(out, cl);
        out.write(b); writeShortLE(out, 0);
    }

    private static int findString(List<String> list, String target) {
        for (int i = 0; i < list.size(); i++) if (target.equals(list.get(i))) return i;
        return -1;
    }

    private static void writeShortLE(ByteArrayOutputStream out, int v) {
        out.write(v & 0xFF); out.write((v >> 8) & 0xFF);
    }

    private static void writeIntLE(ByteArrayOutputStream out, int v) {
        out.write(v & 0xFF); out.write((v >> 8) & 0xFF);
        out.write((v >> 16) & 0xFF); out.write((v >> 24) & 0xFF);
    }
}
