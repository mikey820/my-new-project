package com.mitmpatcher.app;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.net.Uri;
import android.os.Build;
import androidx.core.content.FileProvider;
import java.io.*;

/**
 * Handles uninstall and install via system intents and PackageInstaller.
 */
public class InstallHelper {

    /** Launch system uninstall dialog for the given package. */
    public static void promptUninstall(Context ctx, String packageName) {
        Intent intent = new Intent(Intent.ACTION_DELETE);
        intent.setData(Uri.parse("package:" + packageName));
        ctx.startActivity(intent);
    }

    /** Launch the system installer for the patched APK file. */
    public static void promptInstall(Context ctx, File apkFile) throws IOException {
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_GRANT_READ_URI_PERMISSION);

        Uri uri = FileProvider.getUriForFile(ctx,
                ctx.getPackageName() + ".provider", apkFile);
        intent.setDataAndType(uri, "application/vnd.android.package-archive");
        ctx.startActivity(intent);
    }
}
