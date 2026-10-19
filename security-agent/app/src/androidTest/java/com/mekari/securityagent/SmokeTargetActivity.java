package com.mekari.securityagent;

import android.app.Activity;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

/** Harmless test-APK-only target; absent from the production manifest and APK. */
public final class SmokeTargetActivity extends Activity {
    public static final String TEST_USERNAME = "SMOKE-USER-日本語-🔐";
    public static final String TEST_PASSWORD = "SMOKE-PASS-秘密-🛡️";

    private EditText username;
    private EditText password;
    private TextView status;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setGravity(Gravity.CENTER);
        layout.setPadding(32, 32, 32, 32);
        TextView heading = new TextView(this);
        heading.setText("Controlled assessment smoke target");
        heading.setTextSize(22f);
        heading.setContentDescription("Smoke target ready");
        layout.addView(heading);

        username = new EditText(this);
        username.setHint("Synthetic username");
        username.setContentDescription("Username");
        username.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_YES);
        layout.addView(username);

        password = new EditText(this);
        password.setHint("Synthetic password");
        password.setContentDescription("Password");
        password.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        password.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_YES);
        layout.addView(password);

        status = new TextView(this);
        TextView continueButton = new TextView(this);
        continueButton.setText("Continue");
        continueButton.setContentDescription("Continue");
        continueButton.setClickable(true);
        continueButton.setFocusable(true);
        continueButton.setOnClickListener(view -> status.setText(
                TEST_USERNAME.equals(username.getText().toString()) && TEST_PASSWORD.equals(password.getText().toString())
                        ? "Credentials accepted"
                        : "Credential mismatch"));
        layout.addView(continueButton);
        layout.addView(status);

        TextView summaryButton = new TextView(this);
        summaryButton.setText("Show summary");
        summaryButton.setContentDescription("Show summary");
        summaryButton.setClickable(true);
        summaryButton.setFocusable(true);
        summaryButton.setOnClickListener(view -> showCredentialFreeSummary());
        layout.addView(summaryButton);
        setContentView(layout, new ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
    }

    private void showCredentialFreeSummary() {
        LinearLayout summary = new LinearLayout(this);
        summary.setOrientation(LinearLayout.VERTICAL);
        summary.setGravity(Gravity.CENTER);
        summary.setPadding(32, 32, 32, 32);
        TextView heading = new TextView(this);
        heading.setText("Controlled assessment summary");
        heading.setContentDescription("Assessment summary screen");
        heading.setTextSize(22f);
        summary.addView(heading);
        TextView detail = new TextView(this);
        detail.setText("No credentials are displayed on this screen.");
        summary.addView(detail);
        setContentView(summary, new ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
    }
}
