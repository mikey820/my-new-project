package com.mitmpatcher.app;

import android.os.Bundle;
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

    private ProgressBar progressBar;
    private TextView    progressPercent;
    private RecyclerView logRecycler;
    private Button      uninstallBtn;
    private Button      installBtn;
    private LogAdapter  logAdapter;

    private File patchedApk;
    private String packageName;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_patch);

        packageName = getIntent().getStringExtra(EXTRA_PACKAGE_NAME);
        String appName = getIntent().getStringExtra(EXTRA_APP_NAME);
        setTitle("Patching: " + appName);
        if (getSupportActionBar() != null) getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        progressBar    = findViewById(R.id.progress_bar);
        progressPercent = findViewById(R.id.progress_percent);
        logRecycler    = findViewById(R.id.log_recycler);
        uninstallBtn   = findViewById(R.id.btn_uninstall);
        installBtn     = findViewById(R.id.btn_install);

        List<String> logs = new ArrayList<>();
        logAdapter = new LogAdapter(logs);
        logRecycler.setLayoutManager(new LinearLayoutManager(this));
        logRecycler.setAdapter(logAdapter);

        uninstallBtn.setOnClickListener(v -> confirmUninstall());
        installBtn.setOnClickListener(v -> {
            if (patchedApk != null) {
                try { InstallHelper.promptInstall(this, patchedApk); }
                catch (Exception e) { showError("Install error: " + e.getMessage()); }
            }
        });

        startPatch();
    }

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
                runOnUiThread(() -> {
                    progressBar.setProgress(100);
                    progressPercent.setText("Complete!");
                    uninstallBtn.setVisibility(View.VISIBLE);
                    installBtn.setVisibility(View.VISIBLE);
                    logAdapter.add("─────────────────────────────────");
                    logAdapter.add("Tap UNINSTALL, then INSTALL PATCHED APK");
                    logRecycler.smoothScrollToPosition(logAdapter.getItemCount() - 1);
                });
            }
            @Override public void onError(String msg) {
                runOnUiThread(() -> showError(msg));
            }
        });
    }

    private void confirmUninstall() {
        new AlertDialog.Builder(this)
                .setTitle("Uninstall original?")
                .setMessage("This will remove the original app. Install the patched APK immediately after.")
                .setPositiveButton("Uninstall", (d, w) ->
                        InstallHelper.promptUninstall(this, packageName))
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void showError(String msg) {
        logAdapter.add("ERROR: " + msg);
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
            tv.setPadding(16, 4, 16, 4);
            tv.setFontFeatureSettings("tnum");
            tv.setTypeface(android.graphics.Typeface.MONOSPACE);
            return new VH(tv);
        }
        @Override public void onBindViewHolder(VH h, int pos) {
            String msg = items.get(pos);
            ((TextView) h.itemView).setText(msg);
            int color = msg.startsWith("ERROR")
                    ? 0xFFE53935
                    : msg.startsWith("Done") ? 0xFF43A047
                    : 0xFF212121;
            ((TextView) h.itemView).setTextColor(color);
        }
        @Override public int getItemCount() { return items.size(); }

        static class VH extends RecyclerView.ViewHolder {
            VH(android.view.View v) { super(v); }
        }
    }
}
