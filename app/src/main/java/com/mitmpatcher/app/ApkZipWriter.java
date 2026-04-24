package com.mitmpatcher.app;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.zip.*;

/**
 * ZipOutputStream wrapper that:
 *   • preserves per-entry compression method
 *   • 4-byte aligns STORED entries (required for resources.arsc and lib/*.so on API 30+)
 *   • computes CRC/size for STORED entries
 *
 * Android 11+ rejects APKs where resources.arsc is deflated or unaligned.
 */
class ApkZipWriter implements Closeable {

    private final CountingOutputStream counting;
    private final ZipOutputStream zos;

    ApkZipWriter(File output) throws IOException {
        counting = new CountingOutputStream(new BufferedOutputStream(new FileOutputStream(output)));
        zos = new ZipOutputStream(counting);
        zos.setLevel(Deflater.DEFAULT_COMPRESSION);
    }

    void writeEntry(String name, byte[] data, int method) throws IOException {
        ZipEntry ze = new ZipEntry(name);
        ze.setMethod(method);

        if (method == ZipEntry.STORED) {
            CRC32 crc = new CRC32();
            crc.update(data);
            ze.setCrc(crc.getValue());
            ze.setSize(data.length);
            ze.setCompressedSize(data.length);

            // Pad the local file header so the data payload lands on a 4-byte boundary.
            // Local file header = 30 bytes + name + extra, data starts immediately after.
            int nameLen = name.getBytes(StandardCharsets.UTF_8).length;
            long dataStartIfNoExtra = counting.count + 30 + nameLen;
            int pad = (int) ((4 - (dataStartIfNoExtra % 4)) % 4);
            if (pad > 0) {
                ze.setExtra(new byte[pad]);
            }
        }

        zos.putNextEntry(ze);
        zos.write(data);
        zos.closeEntry();
    }

    @Override
    public void close() throws IOException {
        zos.close();
    }

    /** Tracks bytes written so we can compute alignment padding before each entry. */
    private static final class CountingOutputStream extends FilterOutputStream {
        long count = 0;

        CountingOutputStream(OutputStream o) { super(o); }

        @Override public void write(int b) throws IOException {
            out.write(b);
            count++;
        }

        @Override public void write(byte[] b, int off, int len) throws IOException {
            out.write(b, off, len);
            count += len;
        }
    }
}
