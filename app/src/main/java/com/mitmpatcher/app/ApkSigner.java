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

        File signedApk = new File(ctx.getCacheDir(), "signed_" + unsignedApk.getName());
        signJar(unsignedApk, signedApk, pk, cert, log);
        return signedApk;
    }

    // -----------------------------------------------------------------------
    // V1 JAR signing
    // -----------------------------------------------------------------------

    private void signJar(File input, File output, PrivateKey pk, X509Certificate cert,
            Logger log) throws Exception {

        log.log("Opening APK for signing…");
        ZipFile zf = new ZipFile(input);
        Map<String, byte[]> entryData = new LinkedHashMap<>();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        // Phase 1 — compute per-entry SHA-256 digests
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

        // Phase 6 — write output ZIP
        log.log("Writing signed APK to " + output.getName() + "…");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(output))) {
            zos.setLevel(Deflater.NO_COMPRESSION);
            for (Map.Entry<String, byte[]> e : entryData.entrySet()) {
                ZipEntry ze = new ZipEntry(e.getKey());
                zos.putNextEntry(ze);
                zos.write(e.getValue());
                zos.closeEntry();
            }
            putMeta(zos, "META-INF/MANIFEST.MF", mfBytes);
            putMeta(zos, "META-INF/CERT.SF",     sfBytes);
            putMeta(zos, "META-INF/CERT.RSA",    pkcs7Der);
        }
        log.log("Signed APK written (" + (output.length() / 1024) + " KB)");
    }

    private static void putMeta(ZipOutputStream zos, String name, byte[] data)
            throws IOException {
        zos.putNextEntry(new ZipEntry(name));
        zos.write(data);
        zos.closeEntry();
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
