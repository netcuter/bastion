/**
 * Vulnerable Mobile Banking Application (Android)
 * Realistic example for mobile testing engine
 */
package com.example.banking;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;
import android.webkit.WebView;
import android.widget.EditText;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;

public class MainActivity extends Activity {

    // VULNERABILITY: Hardcoded API credentials
    // NOTE: Intentionally FAKE keys for vulnerability demonstration
    private static final String API_KEY = "sk_test_FAKE_EXAMPLE_NOT_REAL_xyz";
    private static final String API_SECRET = "secret_FAKE_EXAMPLE_NOT_REAL_xyz123";

    // VULNERABILITY: Hardcoded encryption key
    private static final String ENCRYPTION_KEY = "MySecretKey12345";

    // VULNERABILITY: Debug mode enabled
    private static final boolean DEBUG = true;

    private SharedPreferences prefs;
    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        prefs = getSharedPreferences("user_data", MODE_PRIVATE);

        // VULNERABILITY: Insecure data storage
        storeUserCredentials("user@example.com", "password123");

        // VULNERABILITY: Disabled SSL certificate validation
        disableSSLCertificateChecking();

        // Initialize WebView with vulnerabilities
        initWebView();
    }

    /**
     * Login function
     * VULNERABILITY: SQL Injection via local SQLite
     */
    public void performLogin(String username, String password) {
        // VULNERABILITY: SQL Injection
        String query = "SELECT * FROM users WHERE username = '" + username +
                      "' AND password = '" + password + "'";

        // VULNERABILITY: Logging sensitive data
        Log.d("LoginActivity", "Login attempt: " + username + " / " + password);

        // Execute query (vulnerable to SQL injection)
        // SQLiteDatabase db = getDatabase();
        // Cursor cursor = db.rawQuery(query, null);
    }

    /**
     * Store user credentials
     * VULNERABILITY: Insecure data storage in SharedPreferences
     */
    private void storeUserCredentials(String email, String password) {
        SharedPreferences.Editor editor = prefs.edit();

        // VULNERABILITY: Storing credentials in plain text
        editor.putString("email", email);
        editor.putString("password", password);
        editor.putString("pin", "1234");
        editor.putString("account_number", "123456789");
        editor.apply();

        // VULNERABILITY: Logging sensitive data
        if (DEBUG) {
            Log.d("MainActivity", "Stored credentials: " + email + " / " + password);
        }
    }

    /**
     * Disable SSL certificate validation
     * VULNERABILITY: Accepting all SSL certificates
     */
    private void disableSSLCertificateChecking() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    // VULNERABILITY: Trust all certificates
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }
            };

            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // VULNERABILITY: Trust all hostnames
            HostnameVerifier allHostsValid = (hostname, session) -> true;
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Initialize WebView
     * VULNERABILITY: Insecure WebView configuration
     */
    private void initWebView() {
        webView = findViewById(R.id.webview);

        // VULNERABILITY: JavaScript enabled without proper validation
        webView.getSettings().setJavaScriptEnabled(true);

        // VULNERABILITY: File access enabled
        webView.getSettings().setAllowFileAccess(true);
        webView.getSettings().setAllowContentAccess(true);

        // VULNERABILITY: Mixed content allowed
        webView.getSettings().setMixedContentMode(0); // MIXED_CONTENT_ALWAYS_ALLOW
    }

    /**
     * Make API request
     * VULNERABILITY: Insecure HTTP communication
     */
    private void makeAPIRequest(String endpoint) {
        try {
            // VULNERABILITY: Using HTTP instead of HTTPS
            URL url = new URL("http://api.example.com/" + endpoint);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            // VULNERABILITY: Exposing API key in headers
            conn.setRequestProperty("API-Key", API_KEY);
            conn.setRequestProperty("API-Secret", API_SECRET);

            BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream())
            );
            String response = reader.readLine();

            // VULNERABILITY: Logging API responses (may contain sensitive data)
            Log.d("API", "Response: " + response);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Transfer money
     * VULNERABILITY: Missing transaction validation
     */
    public void transferMoney(String toAccount, String amount) {
        // VULNERABILITY: No input validation
        // VULNERABILITY: No amount limit check
        // VULNERABILITY: No authentication re-verification

        String url = "http://api.bank.com/transfer?to=" + toAccount +
                    "&amount=" + amount + "&from=" + getAccountNumber();

        makeAPIRequest(url);

        Toast.makeText(this, "Transfer successful: $" + amount, Toast.LENGTH_SHORT).show();
    }

    /**
     * Get account number
     * VULNERABILITY: Exposing sensitive data
     */
    private String getAccountNumber() {
        // VULNERABILITY: Reading from insecure storage
        return prefs.getString("account_number", "");
    }

    /**
     * Handle deep link
     * VULNERABILITY: Insecure deep link handling
     */
    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);

        String action = intent.getAction();
        String data = intent.getDataString();

        if (Intent.ACTION_VIEW.equals(action) && data != null) {
            // VULNERABILITY: No validation of deep link data
            // VULNERABILITY: Potential for deep link hijacking
            processDeepLink(data);
        }
    }

    /**
     * Process deep link
     * VULNERABILITY: Command injection via deep link
     */
    private void processDeepLink(String url) {
        // VULNERABILITY: Executing commands from deep link
        if (url.contains("exec://")) {
            String command = url.replace("exec://", "");
            try {
                Runtime.getRuntime().exec(command);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Biometric authentication
     * VULNERABILITY: Weak biometric implementation
     */
    public void authenticateWithBiometric() {
        // VULNERABILITY: No fallback authentication
        // VULNERABILITY: Accepting any biometric result

        boolean isAuthenticated = true; // Always returns true

        if (isAuthenticated) {
            // Grant access without proper validation
            Intent intent = new Intent(this, DashboardActivity.class);
            startActivity(intent);
        }
    }

    /**
     * Export data
     * VULNERABILITY: Insecure data export to external storage
     */
    public void exportUserData() {
        String data = "Email: " + prefs.getString("email", "") + "\n" +
                     "Password: " + prefs.getString("password", "") + "\n" +
                     "PIN: " + prefs.getString("pin", "") + "\n" +
                     "Account: " + prefs.getString("account_number", "");

        // VULNERABILITY: Writing sensitive data to external storage (world-readable)
        try {
            java.io.FileWriter writer = new java.io.FileWriter(
                "/sdcard/user_data.txt"  // VULNERABILITY: External storage
            );
            writer.write(data);
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * OkHttp client with SSL pinning bypass
     * VULNERABILITY: Commented out SSL pinning
     */
    private OkHttpClient getHttpClient() {
        OkHttpClient.Builder builder = new OkHttpClient.Builder();

        // VULNERABILITY: SSL pinning disabled/commented out
        /*
        CertificatePinner certificatePinner = new CertificatePinner.Builder()
            .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .build();
        builder.certificatePinner(certificatePinner);
        */

        return builder.build();
    }

    /**
     * Root detection bypass
     * VULNERABILITY: Weak root detection
     */
    public boolean isDeviceRooted() {
        // VULNERABILITY: Easily bypassed root detection
        String[] paths = {"/system/app/Superuser.apk"};

        for (String path : paths) {
            if (new java.io.File(path).exists()) {
                return true;
            }
        }

        return false; // Default to not rooted
    }

    /**
     * Get device info
     * VULNERABILITY: Information disclosure
     */
    private void sendDeviceInfo() {
        // VULNERABILITY: Collecting and sending sensitive device info
        String deviceInfo = "Device ID: " + android.provider.Settings.Secure.getString(
            getContentResolver(),
            android.provider.Settings.Secure.ANDROID_ID
        );

        deviceInfo += "\nIMEI: " + getIMEI();
        deviceInfo += "\nLocation: " + getLocation();

        // VULNERABILITY: Logging sensitive info
        Log.d("DeviceInfo", deviceInfo);

        // Send to server without encryption
        makeAPIRequest("device-info?data=" + deviceInfo);
    }

    private String getIMEI() {
        // Placeholder
        return "123456789012345";
    }

    private String getLocation() {
        // Placeholder
        return "51.5074,-0.1278";
    }
}
