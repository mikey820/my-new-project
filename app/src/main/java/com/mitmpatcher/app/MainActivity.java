package com.mitmpatcher.app;

import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.AsyncTask;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ProgressBar;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SearchView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private RecyclerView recyclerView;
    private ProgressBar loadingProgress;
    private TextView emptyText;
    private List<AppInfo> allApps = new ArrayList<>();
    private AppAdapter adapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        recyclerView = findViewById(R.id.recycler_view);
        loadingProgress = findViewById(R.id.loading_progress);
        emptyText = findViewById(R.id.empty_text);

        recyclerView.setLayoutManager(new LinearLayoutManager(this));

        new LoadAppsTask().execute();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main_menu, menu);
        MenuItem searchItem = menu.findItem(R.id.action_search);
        SearchView searchView = (SearchView) searchItem.getActionView();
        searchView.setQueryHint("Search apps...");
        searchView.setOnQueryTextListener(new SearchView.OnQueryTextListener() {
            @Override
            public boolean onQueryTextSubmit(String query) { return false; }

            @Override
            public boolean onQueryTextChange(String newText) {
                filterApps(newText);
                return true;
            }
        });
        return true;
    }

    private void filterApps(String query) {
        if (adapter == null) return;
        List<AppInfo> filtered = new ArrayList<>();
        String lower = query.toLowerCase();
        for (AppInfo app : allApps) {
            if (app.getName().toLowerCase().contains(lower)
                    || app.getPackageName().toLowerCase().contains(lower)) {
                filtered.add(app);
            }
        }
        adapter = new AppAdapter(filtered, this::showPatchDialog);
        recyclerView.setAdapter(adapter);
    }

    private void showPatchDialog(AppInfo app) {
        new AlertDialog.Builder(this)
                .setTitle("Patch with MITM?")
                .setMessage("Do you want to patch \"" + app.getName() + "\" to allow MITM inspection?\n\nThis will:\n• Dump the APK\n• Patch the network security config\n• Prompt you to reinstall")
                .setPositiveButton("Patch", (dialog, which) -> {
                    // Step 2 will wire this to PatchActivity
                    startPatch(app);
                })
                .setNegativeButton("Cancel", null)
                .setIcon(app.getIcon())
                .show();
    }

    private void startPatch(AppInfo app) {
        Intent intent = new Intent(this, PatchActivity.class);
        intent.putExtra(PatchActivity.EXTRA_PACKAGE_NAME, app.getPackageName());
        intent.putExtra(PatchActivity.EXTRA_APP_NAME, app.getName());
        startActivity(intent);
    }

    @SuppressWarnings("deprecation")
    private class LoadAppsTask extends AsyncTask<Void, Void, List<AppInfo>> {

        @Override
        protected void onPreExecute() {
            loadingProgress.setVisibility(View.VISIBLE);
            recyclerView.setVisibility(View.GONE);
            emptyText.setVisibility(View.GONE);
        }

        @Override
        protected List<AppInfo> doInBackground(Void... voids) {
            PackageManager pm = getPackageManager();
            List<ApplicationInfo> packages = pm.getInstalledApplications(PackageManager.GET_META_DATA);
            List<AppInfo> result = new ArrayList<>();

            for (ApplicationInfo info : packages) {
                // Skip system apps
                if ((info.flags & ApplicationInfo.FLAG_SYSTEM) != 0) continue;
                // Skip ourselves
                if (info.packageName.equals(getPackageName())) continue;

                String name = pm.getApplicationLabel(info).toString();
                result.add(new AppInfo(name, info.packageName, pm.getApplicationIcon(info)));
            }

            result.sort(Comparator.comparing(a -> a.getName().toLowerCase()));
            return result;
        }

        @Override
        protected void onPostExecute(List<AppInfo> apps) {
            loadingProgress.setVisibility(View.GONE);
            allApps = apps;

            if (apps.isEmpty()) {
                emptyText.setVisibility(View.VISIBLE);
            } else {
                recyclerView.setVisibility(View.VISIBLE);
                adapter = new AppAdapter(apps, MainActivity.this::showPatchDialog);
                recyclerView.setAdapter(adapter);
            }
        }
    }
}
