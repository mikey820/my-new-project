package com.mitmpatcher.app;

import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class PatchActivity extends AppCompatActivity {

    public static final String EXTRA_PACKAGE_NAME = "package_name";
    public static final String EXTRA_APP_NAME     = "app_name";

    private ProgressBar  progressBar;
    private TextView     progressPercent;
    private RecyclerView logRecycler;
    private Button       uninstallBtn;
    private Button       installBtn;
    private LogAdapter   logAdapter;

    private File    patchedApk;
    private String  packageName;
    private boolean patchComplete      = false;
    private boolean uninstallTriggered = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_patch);

        packageName = getIntent().getStringExtra(EXTRA_PACKAGE_NAME);
        String appName = getIntent().getStringExtra(EXTRA_APP_NAME);
        setTitle("Patching: " + appName);
        if (getSupportActionBar() != null) getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        progressBar     = findViewById(R.id.progress_bar);
        progressPercent = findViewById(R.id.progress_percent);
        logRecycler     = findViewById(R.id.log_recycler);
        uninstallBtn    = findViewById(R.id.btn_uninstall);
        installBtn      = findViewById(R.id.btn_install);

        logAdapter = new LogAdapter(new ArrayList<>());
        logRecycler.setLayoutManager(new LinearLayoutManager(this));
        logRecycler.setAdapter(logAdapter);

        uninstallBtn.setOnClickListener(v -> triggerUninstall());
        installBtn.setOnClickListener(v -> triggerInstall());

        startPatch();
    }

    // -----------------------------------------------------------------------
    // onResume — auto-trigger install once the original app is gone
    // -----------------------------------------------------------------------

    @Override
    protected void onResume() {
        super.onResume();
        if (uninstallTriggered && patchedApk != null && !isPackageInstalled(packageName)) {
            uninstallTriggered = false;
            logAdapter.add("Original app uninstalled — launching installer…");
            logRecycler.smoothScrollToPosition(logAdapter.getItemCount() - 1);
            triggerInstall();
        }
    }

    // -----------------------------------------------------------------------
    // Patching
    // -----------------------------------------------------------------------

    private void startPatch() {
        ApkPatcher patcher = new ApkPatcher(this);
        patcher.patch(packageName, new ApkPatcher.Callback() {
            @Override public void onStep(String msg) {
                runOnUiThread(() -> {
                    logAdapter.add(msg);
                    logRecycler.smoothScrollToPosition(logAdapter.getItemCount() - 1);
                });
            }
            @Override public void onProgress(int pct) {
                runOnUiThread(() -> {
                    progressBar.setProgress(pct);
                    progressPercent.setText(pct + "%");
                });
            }
            @Override public void onDone(File apk) {
                patchedApk = apk;
                patchComplete = true;
                runOnUiThread(() -> {
                    progressBar.setProgress(100);
                    progressPercent.setText("Complete!");
                    logAdapter.add("────────────────────────────────────");
                    logAdapter.add("Patching finished — ready to install");
                    logRecycler.smoothScrollToPosition(logAdapter.getItemCount() - 1);
                    uninstallBtn.setVisibility(View.VISIBLE);
                    installBtn.setVisibility(View.VISIBLE);
                    showReadyDialog();
                });
            }
            @Override public void onError(String msg) {
                runOnUiThread(() -> showError(msg));
            }
        });
    }

    // -----------------------------------------------------------------------
    // Install flow
    // -----------------------------------------------------------------------

    /** Step 1 — uninstall original. */
    private void triggerUninstall() {
        uninstallTriggered = true;
        logAdapter.add("Launching system uninstall dialog…");
        logRecycler.smoothScrollToPosition(logAdapter.getItemCount() - 1);
        InstallHelper.promptUninstall(this, packageName);
    }

    /** Step 2 — install patched APK. */
    private void triggerInstall() {
        if (patchedApk == null) return;
        logAdapter.add("Launching installer for patched APK…");
        new Handler(Looper.getMainLooper()).post(() -> {
            try {
                InstallHelper.promptInstall(this, patchedApk);
            } catch (Exception e) {
                showError("Install error: " + e.getMessage());
            }
        });
    }

    /** Auto-shown when patching finishes — walks the user through both steps. */
    private void showReadyDialog() {
        new AlertDialog.Builder(this)
                .setTitle("Patch complete!")
                .setMessage(
                    "The patched APK is ready.\n\n" +
                    "Step 1 → Tap \"Uninstall\" to remove the original app.\n\n" +
                    "Step 2 → The installer will open automatically when uninstall finishes.\n\n" +
                    "Tap below to start uninstalling now.")
                .setPositiveButton("Uninstall now", (d, w) -> triggerUninstall())
                .setNegativeButton("I'll do it manually", null)
                .setCancelable(false)
                .show();
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private boolean isPackageInstalled(String pkg) {
        try {
            getPackageManager().getApplicationInfo(pkg, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    private void showError(String msg) {
        logAdapter.add("ERROR: " + msg);
        logRecycler.smoothScrollToPosition(logAdapter.getItemCount() - 1);
        new AlertDialog.Builder(this)
                .setTitle("Error")
                .setMessage(msg)
                .setPositiveButton("OK", null)
                .show();
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) { onBackPressed(); return true; }
        return super.onOptionsItemSelected(item);
    }

    // -----------------------------------------------------------------------
    // Log adapter
    // -----------------------------------------------------------------------

    private static class LogAdapter extends RecyclerView.Adapter<LogAdapter.VH> {
        private final List<String> items;
        LogAdapter(List<String> items) { this.items = items; }

        void add(String msg) {
            items.add(msg);
            notifyItemInserted(items.size() - 1);
        }

        @Override public VH onCreateViewHolder(android.view.ViewGroup p, int t) {
            TextView tv = new TextView(p.getContext());
            tv.setTextSize(12);
            tv.setPadding(24, 5, 24, 5);
            tv.setTypeface(android.graphics.Typeface.MONOSPACE);
            return new VH(tv);
        }

        @Override public void onBindViewHolder(VH h, int pos) {
            String msg = items.get(pos);
            ((TextView) h.itemView).setText(msg);
            int color;
            if (msg.startsWith("ERROR"))               color = 0xFFE53935;
            else if (msg.startsWith("──"))             color = 0xFF9E9E9E;
            else if (msg.contains("finished") ||
                     msg.contains("complete") ||
                     msg.contains("signed") ||
                     msg.startsWith("Done"))           color = 0xFF43A047;
            else if (msg.startsWith("  [sign]"))       color = 0xFF1565C0;
            else                                       color = 0xFF212121;
            ((TextView) h.itemView).setTextColor(color);
        }

        @Override public int getItemCount() { return items.size(); }

        static class VH extends RecyclerView.ViewHolder {
            VH(android.view.View v) { super(v); }
        }
    }
}
