package com.mitmpatcher.app;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import java.io.*;
import java.util.zip.*;

/**
 * Orchestrates the full APK patch pipeline:
 *   extract → patch manifest + resources.arsc → add network_security_config.xml
 *   → strip META-INF → re-zip → sign
 */
public class ApkPatcher {

    public interface Callback {
        void onStep(String message);
        void onProgress(int percent);
        void onDone(File signedApk);
        void onError(String message);
    }

    // Matches apk-mitm exactly: trust system + user CAs, allow cleartext (HTTP) traffic
    // https://github.com/niklashigi/apk-mitm
    private static final String NETWORK_SECURITY_CONFIG_XML =
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
            "<network-security-config>\n" +
            "    <base-config cleartextTrafficPermitted=\"true\">\n" +
            "        <trust-anchors>\n" +
            "            <certificates src=\"system\" />\n" +
            "            <certificates src=\"user\" />\n" +
            "        </trust-anchors>\n" +
            "    </base-config>\n" +
            "</network-security-config>";

    private final Context ctx;

    public ApkPatcher(Context ctx) { this.ctx = ctx; }

    public void patch(String packageName, Callback cb) {
        new Thread(() -> {
            try {
                doPatch(packageName, cb);
            } catch (Exception e) {
                String msg = e.getMessage();
                if (msg == null || msg.isEmpty()) msg = e.getClass().getSimpleName();
                cb.onError("Unexpected error: " + msg + " (" + e.getClass().getSimpleName() + ")");
            }
        }, "apk-patcher").start();
    }

    private void doPatch(String packageName, Callback cb) throws Exception {
        // ── 1. Locate source APK ──────────────────────────────────────────────
        cb.onStep("Locating APK…");
        cb.onProgress(5);
        PackageManager pm = ctx.getPackageManager();
        ApplicationInfo ai = pm.getApplicationInfo(packageName, 0);
        File sourceApk = new File(ai.sourceDir);
        if (!sourceApk.exists()) { cb.onError("APK not found at: " + ai.sourceDir); return; }
        cb.onStep("Found: " + sourceApk.getAbsolutePath());

        // ── 2. Copy APK to work dir ───────────────────────────────────────────
        cb.onStep("Copying APK to work directory…");
        cb.onProgress(10);
        File workDir = new File(ctx.getCacheDir(), "patch_" + packageName);
        workDir.mkdirs();
        File workApk = new File(workDir, "base.apk");
        copyFile(sourceApk, workApk);
        cb.onStep("Copied (" + (workApk.length() / 1024) + " KB)");

        // ── 3. Read manifest and resources.arsc ──────────────────────────────
        cb.onStep("Reading AndroidManifest.xml…");
        cb.onProgress(20);
        byte[] manifest = readZipEntry(workApk, "AndroidManifest.xml");
        if (manifest == null) { cb.onError("AndroidManifest.xml not found in APK"); return; }

        cb.onStep("Reading resources.arsc…");
        cb.onProgress(30);
        byte[] arsc = readZipEntry(workApk, "resources.arsc");
        if (arsc == null) { cb.onError("resources.arsc not found in APK"); return; }

        // ── 4. Resolve / create network_security_config resource ID ──────────
        cb.onStep("Resolving xml resource ID…");
        cb.onProgress(40);
        ResourcesArscEditor.Result arscResult = ResourcesArscEditor.process(arsc);
        int xmlResId = arscResult.resourceId;
        if (arscResult.patchedArsc != null) {
            cb.onStep(String.format("Added xml resource ID: 0x%08x", xmlResId));
            arsc = arscResult.patchedArsc;
        } else {
            cb.onStep(String.format("Reusing existing xml resource ID: 0x%08x", xmlResId));
        }

        // ── 5. Patch binary manifest ──────────────────────────────────────────
        cb.onStep("Patching AndroidManifest.xml…");
        cb.onProgress(55);
        byte[] patchedManifest = BinaryXmlEditor.patch(manifest, xmlResId);
        cb.onStep("Manifest patched — networkSecurityConfig injected");

        // ── 6. Rebuild APK zip ───────────────────────────────────────────────
        cb.onStep("Rebuilding APK…");
        cb.onProgress(65);
        File patchedApk = new File(workDir, "patched.apk");
        rebuildApk(workApk, patchedApk, patchedManifest, arscResult.patchedArsc != null ? arsc : null);
        cb.onStep("APK rebuilt (" + (patchedApk.length() / 1024) + " KB)");

        // ── 7. Sign ───────────────────────────────────────────────────────────
        cb.onStep("─── Signing APK (V1 JAR) ───");
        cb.onProgress(80);
        ApkSigner signer = new ApkSigner(ctx);
        final int[] signingProgress = {80};
        File signedApk = signer.sign(patchedApk, msg -> {
            cb.onStep("  [sign] " + msg);
            if (signingProgress[0] < 97) {
                signingProgress[0] += 3;
                cb.onProgress(signingProgress[0]);
            }
        });
        cb.onStep("APK signed successfully → " + signedApk.getName());

        // ── 8. Done ───────────────────────────────────────────────────────────
        cb.onProgress(100);
        cb.onStep("Done!");
        cb.onDone(signedApk);
    }

    // -----------------------------------------------------------------------
    // Rebuild ZIP: copy all entries, replace manifest/arsc, strip META-INF
    // -----------------------------------------------------------------------

    private void rebuildApk(File src, File dst, byte[] newManifest, byte[] newArsc)
            throws IOException {

        try (ZipFile  zin  = new ZipFile(src);
             ZipOutputStream zout = new ZipOutputStream(new FileOutputStream(dst))) {

            zout.setLevel(ZipEntry.DEFLATED);
            java.util.Enumeration<? extends ZipEntry> entries = zin.entries();

            boolean nscWritten = false;
            while (entries.hasMoreElements()) {
                ZipEntry ze = entries.nextElement();
                String name = ze.getName();

                // Drop old signature files
                if (name.startsWith("META-INF/")) continue;
                // Replace network_security_config if it already exists (we'll re-add ours below)
                if (name.equals("res/xml/network_security_config.xml")) { nscWritten = false; continue; }

                byte[] data;
                if (name.equals("AndroidManifest.xml")) {
                    data = newManifest;
                } else if (name.equals("resources.arsc") && newArsc != null) {
                    data = newArsc;
                } else {
                    data = readEntry(zin, ze);
                }

                ZipEntry out = new ZipEntry(name);
                zout.putNextEntry(out);
                zout.write(data);
                zout.closeEntry();
            }

            // Always write our network_security_config.xml
            byte[] nscBytes = NETWORK_SECURITY_CONFIG_XML.getBytes("UTF-8");
            ZipEntry nscEntry = new ZipEntry("res/xml/network_security_config.xml");
            zout.putNextEntry(nscEntry);
            zout.write(nscBytes);
            zout.closeEntry();
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    static byte[] readZipEntry(File apk, String entryName) throws IOException {
        try (ZipFile zf = new ZipFile(apk)) {
            ZipEntry ze = zf.getEntry(entryName);
            if (ze == null) return null;
            return readEntry(zf, ze);
        }
    }

    private static byte[] readEntry(ZipFile zf, ZipEntry ze) throws IOException {
        try (InputStream is = zf.getInputStream(ze)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream((int) Math.max(ze.getSize(), 0));
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) out.write(buf, 0, n);
            return out.toByteArray();
        }
    }

    private static void copyFile(File src, File dst) throws IOException {
        try (InputStream in  = new FileInputStream(src);
             OutputStream out = new FileOutputStream(dst)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
        }
    }
}
