package com.mitmpatcher.app;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.jar.*;
import java.util.zip.*;

/**
 * V1 (JAR) APK signer backed by the Android Keystore.
 * Key generation is one-time; the key is persisted in hardware-backed secure storage.
 */
public class ApkSigner {

    public interface Logger {
        void log(String message);
    }

    private static final String KEY_ALIAS = "mitm_patcher_v1";

    private final Context ctx;

    public ApkSigner(Context ctx) {
        this.ctx = ctx;
    }

    // -----------------------------------------------------------------------
    // Public entry point
    // -----------------------------------------------------------------------

    public File sign(File unsignedApk, Logger log) throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);

        if (!ks.containsAlias(KEY_ALIAS)) {
            log.log("Generating RSA-2048 signing key (one-time setup)…");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            kpg.initialize(new KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN)
                    .setKeySize(2048)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setCertificateSubject(new X500Principal("CN=MitmPatcher"))
                    .setCertificateSerialNumber(BigInteger.ONE)
                    .setCertificateNotBefore(new Date())
                    .setCertificateNotAfter(new Date(
                            System.currentTimeMillis() + 30L * 365 * 24 * 60 * 60 * 1000))
                    .build());
            kpg.generateKeyPair();
            log.log("Signing key created and stored in Android Keystore");
        } else {
            log.log("Reusing existing key from Android Keystore");
        }

        PrivateKey    pk   = (PrivateKey)    ks.getKey(KEY_ALIAS, null);
        X509Certificate cert = (X509Certificate) ks.getCertificate(KEY_ALIAS);
        log.log("Key loaded — subject: " + cert.getSubjectX500Principal().getName());

        File v1Apk = new File(ctx.getCacheDir(), "v1_" + unsignedApk.getName());
        signJar(unsignedApk, v1Apk, pk, cert, log);

        log.log("─── Applying APK Signature Scheme v2 ───");
        File signedApk = new File(ctx.getCacheDir(), "signed_" + unsignedApk.getName());
        signV2(v1Apk, signedApk, pk, cert, log);
        v1Apk.delete();
        return signedApk;
    }

    // -----------------------------------------------------------------------
    // V1 JAR signing
    // -----------------------------------------------------------------------

    private void signJar(File input, File output, PrivateKey pk, X509Certificate cert,
            Logger log) throws Exception {

        log.log("Opening APK for signing…");
        ZipFile zf = new ZipFile(input);
        Map<String, byte[]>  entryData   = new LinkedHashMap<>();
        Map<String, Integer> entryMethod = new LinkedHashMap<>();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        // Phase 1 — compute per-entry SHA-256 digests (preserving original method)
        log.log("Computing SHA-256 digests for " + zf.size() + " entries…");
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(new Attributes.Name("Created-By"), "MitmPatcher");

        int processed = 0;
        Enumeration<? extends ZipEntry> entries = zf.entries();
        while (entries.hasMoreElements()) {
            ZipEntry ze = entries.nextElement();
            if (ze.getName().startsWith("META-INF/")) continue;
            byte[] data = readEntry(zf, ze);
            entryData.put(ze.getName(), data);
            entryMethod.put(ze.getName(), ze.getMethod());
            sha256.reset();
            byte[] digest = sha256.digest(data);
            Attributes attrs = new Attributes();
            attrs.putValue("SHA-256-Digest", Base64.getEncoder().encodeToString(digest));
            manifest.getEntries().put(ze.getName(), attrs);
            processed++;
            if (processed % 50 == 0) log.log("  Digested " + processed + " entries…");
        }
        zf.close();
        log.log("All " + processed + " entry digests computed");

        // Phase 2 — MANIFEST.MF
        log.log("Building MANIFEST.MF…");
        ByteArrayOutputStream mfBaos = new ByteArrayOutputStream();
        manifest.write(mfBaos);
        byte[] mfBytes = mfBaos.toByteArray();

        // Phase 3 — CERT.SF (digest of manifest + per-section digests)
        log.log("Building CERT.SF…");
        sha256.reset();
        byte[] mfDigest = sha256.digest(mfBytes);
        StringBuilder sf = new StringBuilder();
        sf.append("Signature-Version: 1.0\r\n");
        sf.append("SHA-256-Digest-Manifest: ")
          .append(Base64.getEncoder().encodeToString(mfDigest)).append("\r\n");
        sf.append("Created-By: MitmPatcher\r\n\r\n");

        for (Map.Entry<String, Attributes> e : manifest.getEntries().entrySet()) {
            String section = "Name: " + e.getKey() + "\r\nSHA-256-Digest: "
                    + e.getValue().getValue("SHA-256-Digest") + "\r\n\r\n";
            sha256.reset();
            byte[] sd = sha256.digest(section.getBytes("UTF-8"));
            sf.append("Name: ").append(e.getKey()).append("\r\n");
            sf.append("SHA-256-Digest: ")
              .append(Base64.getEncoder().encodeToString(sd)).append("\r\n\r\n");
        }
        byte[] sfBytes = sf.toString().getBytes("UTF-8");

        // Phase 4 — sign CERT.SF with RSA-SHA256
        log.log("Signing CERT.SF with RSA-SHA256 (AndroidKeyStore)…");
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(pk);
        sig.update(sfBytes);
        byte[] rawSig = sig.sign();
        log.log("Signature size: " + rawSig.length + " bytes");

        // Phase 5 — wrap in PKCS#7 DER
        log.log("Encoding PKCS#7 / CMS SignedData block…");
        byte[] certDer  = cert.getEncoded();
        byte[] pkcs7Der = buildPkcs7(rawSig, certDer, cert);
        log.log("PKCS#7 block: " + pkcs7Der.length + " bytes");

        // Phase 6 — write output ZIP (preserving method + 4-byte aligning STORED entries)
        log.log("Writing signed APK to " + output.getName() + "…");
        try (ApkZipWriter zout = new ApkZipWriter(output)) {
            for (Map.Entry<String, byte[]> e : entryData.entrySet()) {
                String name = e.getKey();
                int method = ApkPatcher.methodFor(name, entryMethod.get(name));
                zout.writeEntry(name, e.getValue(), method);
            }
            zout.writeEntry("META-INF/MANIFEST.MF", mfBytes,  ZipEntry.DEFLATED);
            zout.writeEntry("META-INF/CERT.SF",     sfBytes,  ZipEntry.DEFLATED);
            zout.writeEntry("META-INF/CERT.RSA",    pkcs7Der, ZipEntry.DEFLATED);
        }
        log.log("Signed APK written (" + (output.length() / 1024) + " KB)");
    }

    // -----------------------------------------------------------------------
    // PKCS#7 / CMS SignedData (DER)
    // -----------------------------------------------------------------------

    private static byte[] buildPkcs7(byte[] signature, byte[] certDer, X509Certificate cert)
            throws Exception {
        byte[] sha256Oid = derOid(new int[]{2, 16, 840, 1, 101, 3, 4, 2, 1});
        byte[] rsaOid    = derOid(new int[]{1, 2, 840, 113549, 1, 1, 1});
        byte[] dataOid   = derOid(new int[]{1, 2, 840, 113549, 1, 7, 1});
        byte[] sdOid     = derOid(new int[]{1, 2, 840, 113549, 1, 7, 2});

        // IssuerAndSerialNumber
        byte[] issuer = cert.getIssuerX500Principal().getEncoded();
        byte[] serial = derInt(cert.getSerialNumber());
        byte[] ias    = derSequence(issuer, serial);

        // SignerInfo
        ByteArrayOutputStream si = new ByteArrayOutputStream();
        si.write(derInt(BigInteger.ONE));
        si.write(ias);
        si.write(derSequence(sha256Oid, derNull()));
        si.write(derSequence(rsaOid,    derNull()));
        si.write(derOctetString(signature));
        byte[] signerInfo = derSequence(si.toByteArray());

        // SignedData
        ByteArrayOutputStream sd = new ByteArrayOutputStream();
        sd.write(derInt(BigInteger.ONE));
        sd.write(derSet(derSequence(sha256Oid, derNull())));
        sd.write(derSequence(dataOid));                  // detached ContentInfo
        sd.write(derTag(0xA0, certDer));                 // [0] certificates
        sd.write(derSet(signerInfo));
        byte[] signedData = derSequence(sd.toByteArray());

        // ContentInfo
        ByteArrayOutputStream ci = new ByteArrayOutputStream();
        ci.write(sdOid);
        ci.write(derTag(0xA0, signedData));
        return derSequence(ci.toByteArray());
    }

    // -----------------------------------------------------------------------
    // DER encoding helpers
    // -----------------------------------------------------------------------

    private static byte[] derTag(int tag, byte[] content) throws IOException {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(tag);
        writeLen(o, content.length);
        o.write(content);
        return o.toByteArray();
    }

    private static byte[] derSequence(byte[]... parts) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (byte[] p : parts) body.write(p);
        return derTag(0x30, body.toByteArray());
    }

    private static byte[] derSet(byte[]... parts) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (byte[] p : parts) body.write(p);
        return derTag(0x31, body.toByteArray());
    }

    private static byte[] derOid(int[] c) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(c[0] * 40 + c[1]);
        for (int i = 2; i < c.length; i++) {
            int v = c[i];
            if (v < 0x80) { body.write(v); }
            else {
                List<Integer> bytes = new ArrayList<>();
                bytes.add(v & 0x7F);
                for (v >>= 7; v > 0; v >>= 7) bytes.add((v & 0x7F) | 0x80);
                Collections.reverse(bytes);
                for (int b : bytes) body.write(b);
            }
        }
        return derTag(0x06, body.toByteArray());
    }

    private static byte[] derInt(BigInteger v) throws IOException {
        return derTag(0x02, v.toByteArray());
    }

    private static byte[] derNull() throws IOException { return derTag(0x05, new byte[0]); }

    private static byte[] derOctetString(byte[] d) throws IOException { return derTag(0x04, d); }

    private static void writeLen(OutputStream o, int len) throws IOException {
        if (len < 128)       { o.write(len); }
        else if (len < 256)  { o.write(0x81); o.write(len); }
        else                 { o.write(0x82); o.write((len >> 8) & 0xFF); o.write(len & 0xFF); }
    }

    // -----------------------------------------------------------------------
    // APK Signature Scheme v2
    // (required on Android 11+ for APKs targeting API 30+)
    // https://source.android.com/docs/security/features/apksigning/v2
    // -----------------------------------------------------------------------

    private static final byte[] APK_SIG_BLOCK_MAGIC =
            "APK Sig Block 42".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    private static final int V2_BLOCK_ID                = 0x7109871a;
    private static final int SIG_ALGO_RSA_PKCS1_SHA256  = 0x0103;
    private static final int CHUNK_SIZE                 = 1024 * 1024;

    private void signV2(File input, File output, PrivateKey pk, X509Certificate cert,
            Logger log) throws Exception {

        log.log("Reading v1-signed APK (" + input.length() + " bytes)…");
        byte[] apk = readAllBytes(input);

        // ── Locate ZIP End-Of-Central-Directory ──
        int eocdOffset = findEocd(apk);
        if (eocdOffset < 0) throw new IOException("EOCD not found in APK");
        int cdSize   = readUint32Le(apk, eocdOffset + 12);
        int cdOffset = readUint32Le(apk, eocdOffset + 16);
        log.log("ZIP layout: entries=0..." + cdOffset + ", CD=" + cdSize + "B @" + cdOffset
                + ", EOCD @" + eocdOffset);

        // ── Compute chunked APK digest over entries + CD + EOCD ──
        log.log("Computing chunked SHA-256 digest…");
        byte[] apkDigest = computeApkChunkDigest(apk, cdOffset, eocdOffset);
        log.log("APK digest: " + bytesToHex(apkDigest, 8) + "…");

        // ── Build signed data, sign it ──
        byte[] signedData = buildSignedData(apkDigest, cert);
        log.log("Signing signed-data (" + signedData.length + " bytes) with RSA-SHA256…");
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(pk);
        sig.update(signedData);
        byte[] signature = sig.sign();

        byte[] pubKeyDer = cert.getPublicKey().getEncoded();

        // ── Build v2 block value and outer signing block ──
        byte[] v2BlockValue = buildV2BlockValue(signedData, signature, pubKeyDer);
        byte[] signingBlock = buildSigningBlock(v2BlockValue);
        log.log("Signing block built (" + signingBlock.length + " bytes)");

        // ── Write output APK with signing block inserted before CD ──
        log.log("Writing v2-signed APK…");
        try (OutputStream out = new BufferedOutputStream(new FileOutputStream(output))) {
            out.write(apk, 0, cdOffset);            // ZIP entries
            out.write(signingBlock);                // APK Signing Block (new)
            out.write(apk, cdOffset, cdSize);       // Central Directory

            // EOCD with patched CD offset
            int newCdOffset = cdOffset + signingBlock.length;
            byte[] eocd = java.util.Arrays.copyOfRange(apk, eocdOffset, apk.length);
            writeUint32Le(eocd, 16, newCdOffset);
            out.write(eocd);
        }
        log.log("v2 signature applied ✔");
    }

    // ---- APK digest (chunked SHA-256 per v2 spec) ----

    private static byte[] computeApkChunkDigest(byte[] apk, int cdOffset, int eocdOffset)
            throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        List<byte[]> chunkDigests = new ArrayList<>();

        int[][] regions = { {0, cdOffset}, {cdOffset, eocdOffset}, {eocdOffset, apk.length} };
        for (int[] r : regions) {
            for (int off = r[0]; off < r[1]; off += CHUNK_SIZE) {
                int len = Math.min(CHUNK_SIZE, r[1] - off);
                md.reset();
                md.update((byte) 0xa5);
                md.update(leUint32(len));
                md.update(apk, off, len);
                chunkDigests.add(md.digest());
            }
        }

        md.reset();
        md.update((byte) 0x5a);
        md.update(leUint32(chunkDigests.size()));
        for (byte[] cd : chunkDigests) md.update(cd);
        return md.digest();
    }

    // ---- v2 block builders ----

    private static byte[] buildSignedData(byte[] apkDigest, X509Certificate cert) throws Exception {
        // digests: LP sequence of LP (algoId + LP digest)
        ByteArrayOutputStream digestEntry = new ByteArrayOutputStream();
        digestEntry.write(leUint32(SIG_ALGO_RSA_PKCS1_SHA256));
        digestEntry.write(lengthPrefixed(apkDigest));
        byte[] digestsSection = lengthPrefixed(lengthPrefixed(digestEntry.toByteArray()));

        // certs: LP sequence of LP X.509 certs
        byte[] certsSection = lengthPrefixed(lengthPrefixed(cert.getEncoded()));

        // additional attributes: empty LP sequence
        byte[] attrsSection = lengthPrefixed(new byte[0]);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(digestsSection);
        out.write(certsSection);
        out.write(attrsSection);
        return out.toByteArray();
    }

    private static byte[] buildV2BlockValue(byte[] signedData, byte[] signature, byte[] pubKey)
            throws IOException {
        // signatures: LP sequence of LP (algoId + LP signature)
        ByteArrayOutputStream sigEntry = new ByteArrayOutputStream();
        sigEntry.write(leUint32(SIG_ALGO_RSA_PKCS1_SHA256));
        sigEntry.write(lengthPrefixed(signature));
        byte[] signaturesSection = lengthPrefixed(lengthPrefixed(sigEntry.toByteArray()));

        // signer = LP signedData + LP signatures + LP pubkey
        ByteArrayOutputStream signer = new ByteArrayOutputStream();
        signer.write(lengthPrefixed(signedData));
        signer.write(signaturesSection);
        signer.write(lengthPrefixed(pubKey));

        // v2 block value = LP sequence of LP signers (one signer)
        return lengthPrefixed(lengthPrefixed(signer.toByteArray()));
    }

    private static byte[] buildSigningBlock(byte[] v2BlockValue) throws IOException {
        // One ID-value pair: uint64 pairLen + uint32 id + value
        ByteArrayOutputStream pairContent = new ByteArrayOutputStream();
        pairContent.write(leUint32(V2_BLOCK_ID));
        pairContent.write(v2BlockValue);
        byte[] pair = pairContent.toByteArray();

        long pairLen = pair.length;
        long blockSize = 8 /*pair-len field*/ + pairLen + 8 /*trailing size*/ + 16 /*magic*/;

        ByteArrayOutputStream block = new ByteArrayOutputStream();
        block.write(leUint64(blockSize));
        block.write(leUint64(pairLen));
        block.write(pair);
        block.write(leUint64(blockSize));
        block.write(APK_SIG_BLOCK_MAGIC);
        return block.toByteArray();
    }

    // ---- Binary helpers ----

    private static int findEocd(byte[] apk) {
        int maxSearch = Math.min(apk.length, 65557);
        int startFrom = apk.length - 22;
        int endAt = apk.length - maxSearch;
        for (int i = startFrom; i >= endAt && i >= 0; i--) {
            if (apk[i] == 0x50 && apk[i + 1] == 0x4B
                    && apk[i + 2] == 0x05 && apk[i + 3] == 0x06) {
                int commentLen = (apk[i + 20] & 0xFF) | ((apk[i + 21] & 0xFF) << 8);
                if (i + 22 + commentLen == apk.length) return i;
            }
        }
        return -1;
    }

    private static byte[] lengthPrefixed(byte[] data) throws IOException {
        ByteArrayOutputStream o = new ByteArrayOutputStream(data.length + 4);
        o.write(leUint32(data.length));
        o.write(data);
        return o.toByteArray();
    }

    private static byte[] leUint32(int v) {
        return new byte[] {
                (byte) v, (byte) (v >>> 8), (byte) (v >>> 16), (byte) (v >>> 24) };
    }

    private static byte[] leUint64(long v) {
        byte[] r = new byte[8];
        for (int i = 0; i < 8; i++) r[i] = (byte) (v >>> (i * 8));
        return r;
    }

    private static int readUint32Le(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16) | ((b[off + 3] & 0xFF) << 24);
    }

    private static void writeUint32Le(byte[] b, int off, int v) {
        b[off]     = (byte) v;
        b[off + 1] = (byte) (v >>> 8);
        b[off + 2] = (byte) (v >>> 16);
        b[off + 3] = (byte) (v >>> 24);
    }

    private static byte[] readAllBytes(File f) throws IOException {
        long len = f.length();
        if (len > Integer.MAX_VALUE) throw new IOException("APK too large: " + len);
        byte[] out = new byte[(int) len];
        try (InputStream in = new FileInputStream(f)) {
            int read = 0;
            while (read < out.length) {
                int n = in.read(out, read, out.length - read);
                if (n < 0) throw new EOFException();
                read += n;
            }
        }
        return out;
    }

    private static String bytesToHex(byte[] b, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(n, b.length); i++) sb.append(String.format("%02x", b[i]));
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // Utility
    // -----------------------------------------------------------------------

    private static byte[] readEntry(ZipFile zf, ZipEntry ze) throws IOException {
        try (InputStream is = zf.getInputStream(ze)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream((int) Math.max(ze.getSize(), 0));
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) out.write(buf, 0, n);
            return out.toByteArray();
        }
    }
}
