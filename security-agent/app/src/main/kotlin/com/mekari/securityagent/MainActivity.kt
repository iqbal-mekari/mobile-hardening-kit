package com.mekari.securityagent

import android.app.Activity
import android.app.AlertDialog
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.*
import java.io.OutputStreamWriter
import java.net.URI

class MainActivity : Activity() {
    private lateinit var repo: AgentRepository
    private lateinit var target: EditText
    private lateinit var endpoint: EditText
    private lateinit var model: EditText
    private lateinit var hosts: EditText
    private lateinit var apiKey: EditText
    private lateinit var username: EditText
    private var recoveryMessage: String? = null
    private var cachedRootStatus: String? = null
    private lateinit var password: EditText
    private var recoveryRequired: Boolean = false
    private lateinit var steps: EditText
    private lateinit var cloudConsent: CheckBox
    private lateinit var screenshotConsent: CheckBox
    private lateinit var providerSpinner: Spinner
    private lateinit var modelSpinner: Spinner
    private lateinit var advisoryConsent: CheckBox
    private lateinit var advisoryEndpoint: EditText
    private var fetchingModels = false
    private var pendingLogSessionId: String? = null
    private lateinit var readiness: TextView
    private lateinit var progress: TextView
    private lateinit var report: TextView
    private lateinit var scroll: ScrollView
    private val picker = 731
    private val openAiDefaultEndpoint = "https://api.openai.com/v1/chat/completions"
    private val anthropicDefaultEndpoint = "https://api.anthropic.com/v1/messages"
    private val modelPlaceholder = "Select a fetched model…"
    private val handler = android.os.Handler(android.os.Looper.getMainLooper())
    private var polling = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        window.statusBarColor = 0xfff1f5f9.toInt(); window.navigationBarColor = 0xfff1f5f9.toInt()
        window.decorView.systemUiVisibility = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR or View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR
        repo = AgentRepository(this)
        buildUi()
        if (!AgentService.isRunning) {
            try {
                repo.latestSession()?.takeIf { it.status == SessionStatus.RUNNING }?.let {
                    recoveryRequired = true
                    recoveryMessage = "Interrupted assessment detected. Recover its owned network restriction before resuming."
                    repo.saveSession(it.copy(status = SessionStatus.PAUSED, message = "Previous process stopped; owned network restriction recovery is required before resume. No pending action will be replayed."))
                }
            } catch (e: Exception) { error("Recovery required", e.message ?: "Saved assessment state could not be read.") }
        }
        try { repo.loadConfig()?.let(::populate) } catch (e: Exception) { error("Saved configuration", e.message ?: "Could not read saved configuration") }
        refresh()
    }

    private fun buildUi() {
        scroll = ScrollView(this).apply { setBackgroundColor(0xfff1f5f9.toInt()) }
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(20), dp(18), dp(20), dp(32)) }
        scroll.addView(root); setContentView(scroll)
        root.addView(label("Security assessment", 27, 0xff10243a.toInt(), true))
        root.addView(label("A controlled inspection of an authorized staging app.", 15, 0xff475569.toInt(), false))
        root.addView(section("Device readiness"))
        readiness = label("Checking device…", 15, 0xff334155.toInt(), false); root.addView(readiness)
        root.addView(button("Open accessibility settings") { AgentAccessibilityService.openAccessibilitySettings(this) })
        root.addView(button("Check root access") { checkRoot() })
        root.addView(button("Refresh readiness") { refresh() })
        root.addView(button("Recover stale network restriction") { confirmStaleRecovery() })
        root.addView(section("Target application"))
        target = addField(root, "Installed target package", field("Installed target package", "com.example.staging"))
        root.addView(button("Choose installed app") { chooseTarget() })
        root.addView(button("Install staging APK") { chooseApk() })
        root.addView(fieldLabel("Manual package entry is allowed; choose only an authorized staging target."))
        root.addView(section("Staging network scope"))
        hosts = addField(root, "Exact allowed hostnames", field("Exact allowed hostnames", "staging.example.test"))
        root.addView(label("Model provider", 14, 0xff334155.toInt(), true))
        providerSpinner = Spinner(this).apply {
            minimumHeight = dp(48); contentDescription = "Model provider"
            background = rounded(0xffffffff.toInt(), 0xffcbd5e1.toInt())
            adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, listOf("OpenAI-compatible", "Anthropic"))
            onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) { onProviderChanged(position == 1) }
                override fun onNothingSelected(parent: AdapterView<*>?) {}
            }
        }
        root.addView(providerSpinner, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(48)))
        endpoint = addField(root, "Model HTTPS endpoint", field("Model HTTPS endpoint", openAiDefaultEndpoint))
        model = addField(root, "Model name", field("Model name", ""))
        root.addView(button("Fetch models") { fetchModels() })
        modelSpinner = Spinner(this).apply {
            minimumHeight = dp(48); contentDescription = "Fetched models"; visibility = View.GONE
            background = rounded(0xffffffff.toInt(), 0xffcbd5e1.toInt())
            onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                    val chosen = parent?.getItemAtPosition(position)?.toString() ?: return
                    if (position > 0 && chosen != modelPlaceholder) model.setText(chosen)
                }
                override fun onNothingSelected(parent: AdapterView<*>?) {}
            }
        }
        root.addView(modelSpinner, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(48)))
        root.addView(section("Cloud and test credentials"))
        apiKey = addField(root, "Cloud API key (encrypted on this device)", secretField("Cloud API key (saved encrypted on this device)"))
        username = addField(root, "Staging username (encrypted on this device)", secretField("Staging username (saved encrypted on this device)"))
        password = addField(root, "Staging password (encrypted on this device)", secretField("Staging password (saved encrypted on this device)"))
        steps = addField(root, "Maximum assessment steps (1–100)", field("Maximum assessment steps (1–100)", "40", android.text.InputType.TYPE_CLASS_NUMBER))
        cloudConsent = CheckBox(this).apply { text = "Allow sanitized text observations to be sent to this endpoint"; setTextColor(0xff10243a.toInt()); minHeight = dp(48) }
        screenshotConsent = CheckBox(this).apply { text = "Allow screenshots to be sent (only when no password nodes are present)"; setTextColor(0xff10243a.toInt()); minHeight = dp(48) }
        advisoryConsent = CheckBox(this).apply { text = "Enable live mobile-security advisory fetch (adds controller egress to the advisory host)"; setTextColor(0xff10243a.toInt()); minHeight = dp(48) }
        root.addView(cloudConsent); root.addView(screenshotConsent); root.addView(advisoryConsent)
        advisoryEndpoint = addField(root, "Advisory feed HTTPS URL (only used when live advisory fetch is enabled)", field("Advisory feed HTTPS URL", "https://advisories.example.test/feed", android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_URI))
        root.addView(fieldLabel("No API key or test credential is sent to reports. Never use production accounts."))
        root.addView(button("Save configuration") { saveConfiguration(false) })
        root.addView(section("Assessment session"))
        progress = label("No assessment started.", 15, 0xff334155.toInt(), false); root.addView(progress)
        root.addView(button("Start assessment") { saveConfiguration(true) })
        val controls = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        controls.addView(button("Pause") { service(AgentService.ACTION_PAUSE) }, LinearLayout.LayoutParams(0, dp(52), 1f))
        controls.addView(button("Resume") { resume() }, LinearLayout.LayoutParams(0, dp(52), 1f))
        controls.addView(button("Stop") { service(AgentService.ACTION_STOP) }, LinearLayout.LayoutParams(0, dp(52), 1f))
        root.addView(controls)
        root.addView(button("View retained screenshot evidence") { viewEvidence() })
        root.addView(button("Export Markdown report") { exportReport() })
        root.addView(button("View session log") { viewLog() })
        root.addView(button("Export session log") { exportLog() })
        report = label("Findings and collector coverage will appear here.", 14, 0xff334155.toInt(), false).apply { setTextIsSelectable(true) }
        root.addView(report)
    }

    private fun field(title: String, hint: String, inputType: Int = android.text.InputType.TYPE_CLASS_TEXT): EditText {
        return EditText(this).apply {
            this.hint = hint
            this.inputType = inputType
            minHeight = dp(56)
            setPadding(dp(14), dp(8), dp(14), dp(8))
            setTextColor(0xff10243a.toInt())
            setHintTextColor(0xff64748b.toInt())
            background = rounded(0xffffffff.toInt(), 0xffcbd5e1.toInt())
            contentDescription = title
            tag = title
        }
    }
    private fun addField(root: LinearLayout, title: String, edit: EditText): EditText {
        root.addView(label(title, 14, 0xff334155.toInt(), true))
        root.addView(edit)
        return edit
    }

    private fun secretField(title: String) = field(title, "Enter only if you want to replace the saved value").apply {
        inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        isSaveEnabled = false
        if (Build.VERSION.SDK_INT >= 26) importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
    }

    private fun fieldLabel(text: String) = label(text, 13, 0xff475569.toInt(), false)
    private fun label(text: String, size: Int, color: Int, bold: Boolean) = TextView(this).apply { this.text = text; textSize = size.toFloat(); setTextColor(color); if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD); setPadding(0, dp(6), 0, dp(8)) }
    private fun section(text: String) = TextView(this).apply { this.text = text; textSize = 19f; setTypeface(typeface, android.graphics.Typeface.BOLD); setTextColor(0xff10243a.toInt()); setPadding(0, dp(23), 0, dp(8)) }
    private fun button(text: String, action: () -> Unit) = Button(this).apply {
        this.text = text
        minHeight = dp(48)
        isAllCaps = false
        val primary = text == "Start assessment"
        val caution = text == "Stop"
        backgroundTintList = android.content.res.ColorStateList.valueOf(
            when { primary -> 0xff2563eb.toInt(); caution -> 0xffffedd5.toInt(); else -> 0xffdbeafe.toInt() }
        )
        setTextColor(when {
            primary -> 0xffffffff.toInt()
            caution -> 0xff9a3412.toInt()
            else -> 0xff12304c.toInt()
        })
        setOnClickListener { action() }
    }
    private fun rounded(fill: Int, stroke: Int) = android.graphics.drawable.GradientDrawable().apply { setColor(fill); setStroke(dp(1), stroke); cornerRadius = dp(8).toFloat() }
    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
    private fun populate(c: SessionConfig) { target.setText(c.targetPackage); endpoint.setText(c.endpoint); model.setText(c.model); hosts.setText(c.allowedHosts.joinToString(", ")); steps.setText(c.maxSteps.toString()); cloudConsent.isChecked = c.cloudConsent; screenshotConsent.isChecked = c.screenshotsToCloud
        providerSpinner.setSelection(if (c.provider == ModelProvider.ANTHROPIC) 1 else 0)
        advisoryConsent.isChecked = c.liveAdvisories; advisoryEndpoint.setText(if (c.liveAdvisories) c.advisoryEndpoint else "")
    }
    private fun onProviderChanged(anthropic: Boolean) {
        endpoint.hint = if (anthropic) anthropicDefaultEndpoint else openAiDefaultEndpoint
        val current = endpoint.text.toString().trim()
        if (anthropic && (current.isEmpty() || current == openAiDefaultEndpoint)) endpoint.setText(anthropicDefaultEndpoint)
        else if (!anthropic && current == anthropicDefaultEndpoint) endpoint.setText("")
    }
    private fun selectedProvider() = if (providerSpinner.selectedItemPosition == 1) ModelProvider.ANTHROPIC else ModelProvider.OPENAI

    private fun configuration(forDiscovery: Boolean = false): SessionConfig {
        val t = target.text.toString().trim(); require(t.matches(Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+"))) { "Enter a valid installed package name." }
        val e = endpoint.text.toString().trim(); val uri = URI(e); require(uri.scheme == "https" && uri.host != null && uri.userInfo == null) { "The model endpoint must be a valid HTTPS URL without user information." }
        val m = model.text.toString().trim().let { if (forDiscovery && it.isEmpty()) "model-discovery" else it }; require(m.isNotEmpty() && m.length <= 128) { "Enter the model name." }
        val hs = hosts.text.toString().split(',').map { it.trim().lowercase() }.filter { it.isNotEmpty() }
        require(hs.isNotEmpty() && hs.size <= 32 && hs.all(::isExactHost)) { "Enter exact DNS hostnames or IP literals; wildcards, URLs and user information are not allowed." }
        val max = steps.text.toString().toIntOrNull() ?: 0; require(max in 1..100) { "Maximum steps must be between 1 and 100." }
        require(forDiscovery || cloudConsent.isChecked) { "Consent to sanitized cloud text observations before starting." }
        val advisories = advisoryConsent.isChecked
        val advisoryUrl = if (advisories) advisoryEndpoint.text.toString().trim() else ""
        if (advisories) {
            val au = runCatching { URI(advisoryUrl) }.getOrNull()
            require(advisoryUrl.isNotEmpty() && au != null && au.scheme == "https" && au.host != null && au.userInfo == null && au.fragment == null) { "Enter a valid HTTPS advisory feed URL (no user information or fragment), or disable live advisory fetch." }
        }
        return SessionConfig(t, e, m, hs, max, screenshotConsent.isChecked, cloudConsent.isChecked, selectedProvider(), advisories, advisoryUrl)
    }
    private fun fetchModels() {
        if (fetchingModels) return
        val config: SessionConfig
        val key: String
        try {
            config = configuration(forDiscovery = true)
            ActionPolicy.validateConfig(config)?.let { throw IllegalArgumentException(it) }
            key = apiKey.text.toString().trim().ifEmpty { repo.getSecret("cloud_api_key").orEmpty().trim() }
            require(key.isNotEmpty()) { "Enter a cloud API key (or save one) before fetching models." }
        } catch (e: Exception) { error("Cannot fetch models", e.message ?: "Check the configuration."); return }
        fetchingModels = true
        Toast.makeText(this, "Fetching models…", Toast.LENGTH_SHORT).show()
        Thread {
            val result = runCatching { CloudModelClient().listModels(config, key) }
            runOnUiThread {
                fetchingModels = false
                result.fold({ ids ->
                    val clean = ids.map { it.trim() }.filter { it.isNotEmpty() && it.length <= 128 }.distinct().take(500)
                    if (clean.isEmpty()) error("No models returned", "The endpoint returned no model ids. Enter the model name manually.")
                    else {
                        modelSpinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, listOf(modelPlaceholder) + clean)
                        modelSpinner.setSelection(0); modelSpinner.visibility = View.VISIBLE
                    }
                }, { error("Model fetch failed", it.message ?: "The model list could not be retrieved.") })
            }
        }.start()
    }
    private fun isExactHost(host: String): Boolean {
        if (host.isEmpty() || host.length > 253 || host.any { it.isWhitespace() || it == '*' || it == '/' || it == '@' }) return false
        if (host.matches(Regex("(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}"))) return true
        val ipv4Octet = "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
        if (host.matches(Regex("$ipv4Octet(?:\\.$ipv4Octet){3}"))) return true
        return host.contains(':') && '%' !in host &&
            runCatching { java.net.InetAddress.getByName(host) is java.net.Inet6Address }.getOrDefault(false)
    }
    private fun saveConfiguration(start: Boolean) {
        if (start && AgentService.isRunning) {
            error("Assessment already running", "This device already has an active assessment. Use Pause or Stop before starting another.")
            return
        }
        try {
            val config = configuration(); repo.saveConfig(config)
            if (apiKey.text.isNotEmpty()) repo.setSecret("cloud_api_key", apiKey.text.toString())
            if (username.text.isNotEmpty()) repo.setSecret("username", username.text.toString())
            if (password.text.isNotEmpty()) repo.setSecret("password", password.text.toString())
            apiKey.text.clear(); username.text.clear(); password.text.clear()
            if (start) {
                require(!recoveryRequired) { "Recover the interrupted assessment's owned network restriction before starting or resuming." }
                if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                    requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 704)
                    throw IllegalStateException("Allow notifications, then press Start assessment again so pause and stop controls remain visible.")
                }
                val key = repo.getSecret("cloud_api_key"); require(!key.isNullOrBlank()) { "Enter a cloud API key." }
                val km = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
                val power = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
                require(!km.isKeyguardLocked && power.isInteractive) { "Unlock the screen before starting. The app will not dismiss the lockscreen." }
                require(AgentAccessibilityService.isEnabled(this)) { "Enable Security Assessment inspection in Accessibility settings." }
                require(AgentAccessibilityService.isConnected()) { "Accessibility is enabled but not connected yet; reopen the target or refresh readiness." }
                val session = repo.createSession(config)
                val intent = Intent(this, AgentService::class.java).setAction(AgentService.ACTION_START).putExtra(AgentService.EXTRA_SESSION_ID, session.id)
                if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
                startPolling()
            } else Toast.makeText(this, "Configuration saved securely.", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) { error("Cannot continue", e.message ?: "Check the highlighted configuration.") }
    }
    private fun chooseTarget() {
        val pm = packageManager
        val apps = pm.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0)
            .filter { it.activityInfo.packageName != packageName }.sortedBy { it.loadLabel(pm).toString().lowercase() }
        if (apps.isEmpty()) { error("No installed apps", "Install the authorized staging app or enter its package name manually."); return }
        val labels = apps.map { "${it.loadLabel(pm)}\n${it.activityInfo.packageName}" }.toTypedArray()
        AlertDialog.Builder(this).setTitle("Choose installed app").setItems(labels) { _, index -> target.setText(apps[index].activityInfo.packageName) }.setNegativeButton("Cancel", null).show()
    }
    private fun chooseApk() { startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).setType("application/vnd.android.package-archive").addCategory(Intent.CATEGORY_OPENABLE), picker) }
    @Deprecated("Android document result") override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == picker + 1) { writeReport(requestCode, resultCode, data); return }
        if (requestCode == picker + 2) { writeLog(resultCode, data); return }
        if (requestCode == picker && resultCode == RESULT_OK) {
            val uri: Uri = data?.data ?: return
            try { startActivity(Intent(Intent.ACTION_VIEW).setDataAndType(uri, "application/vnd.android.package-archive").addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)) }
            catch (e: Exception) { error("Cannot open installer", e.message ?: "The package installer is unavailable.") }
        }
    }
    private fun refresh() {
        val km = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        val power = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
        val screenStatus = if (!km.isKeyguardLocked && power.isInteractive) "unlocked and interactive" else "locked or screen off — unlock before running"
        val accessibilityStatus = when {
            AgentAccessibilityService.isConnected() -> "connected"
            AgentAccessibilityService.isEnabled(this) -> "enabled but disconnected; detach host UI automation, then refresh"
            else -> "not enabled"
        }
        readiness.text = "Screen: $screenStatus\nAccessibility: $accessibilityStatus\nRoot: ${rootStatus()}\nNetwork: resolved destination IPs are pinned at session start; shared-IP hosts are not isolated. Cleanup warnings appear in session status.${recoveryMessage?.let { "\n$it" } ?: ""}"
        try { repo.latestSession()?.let(::render) } catch (e: Exception) { error("Saved assessment", e.message ?: "The saved record cannot be read") }
    }
    private fun rootStatus(): String = cachedRootStatus ?: "not checked yet; session start will request MagiskSU approval"
    private fun checkRoot() {
        cachedRootStatus = "checking root access…"
        refresh()
        Thread {
            val result = runCatching { RootShell().run("id", 30_000) }
            val status = result.fold(
                { if (it.exitCode == 0 && it.stdout.contains("uid=0")) "root shell available" else "root access unavailable or not approved" },
                { "root access unavailable: ${it.message ?: "MagiskSU did not grant access"}" }
            )
            runOnUiThread {
                cachedRootStatus = status
                refresh()
            }
        }.start()
    }
    private fun confirmStaleRecovery() {
        if (AgentService.isRunning) {
            error("Assessment active", "Stop the active assessment before recovering a stale network restriction.")
            return
        }
        val latest = try { repo.latestSession() } catch (e: Exception) {
            error("Recovery blocked", e.message ?: "Saved assessment state is unreadable; no firewall changes were made.")
            return
        }
        if (latest?.status == SessionStatus.RUNNING) {
            error("Recovery blocked", "A session is still marked RUNNING. Resume or stop it before recovering a restriction.")
            return
        }
        AlertDialog.Builder(this)
            .setTitle("Recover owned restriction?")
            .setMessage("This will verify the recorded target identity, force-stop that target, and remove only this app's recorded IPv4/IPv6 chains. Other firewall rules are left unchanged.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Recover") { _, _ -> recoverStaleScope() }
            .show()
    }

    private fun recoverStaleScope() {
        Thread {
            val result = runCatching { AndroidDeviceGateway(this).recoverStaleScope() }
            runOnUiThread {
                if (result.isSuccess) {
                    recoveryRequired = false
                    recoveryMessage = result.getOrThrow()
                    refresh()
                } else error("Recovery failed", result.exceptionOrNull()?.message ?: "Owned rules were not confirmed removed.")
            }
        }.start()
    }
    private fun resume() {
        try {
            require(!recoveryRequired) { "Recover the interrupted session's owned network restriction before resuming." }
            val record = repo.latestSession() ?: throw IllegalStateException("No saved assessment to resume.")
            require(record.status == SessionStatus.PAUSED) { "Only a paused assessment can resume." }
            require(AgentAccessibilityService.isEnabled(this)) { "Enable Accessibility before resuming." }
            service(AgentService.ACTION_RESUME, record.id)
        } catch (e: Exception) {
            error("Cannot resume", e.message ?: "Assessment is not resumable.")
        }
    }
    private fun service(action: String, id: String? = null) { startService(Intent(this, AgentService::class.java).setAction(action).putExtra(AgentService.EXTRA_SESSION_ID, id)); startPolling() }
    private fun startPolling() {
        if (polling) return
        polling = true
        handler.post(pollTask)
    }
    private val pollTask = object : Runnable {
        override fun run() {
            if (!polling) return
            if (hasWindowFocus()) refresh()
            handler.postDelayed(this, 1500)
        }
    }
    private fun render(r: SessionRecord) {
        progress.text = "${r.status} — ${r.message}\nSteps: ${r.steps.size} / ${r.config.maxSteps}    Checks: ${r.checks.size}    Findings: ${r.findings.size}"
        val sections = mutableListOf<String>()
        sections += "Collector coverage"
        sections += if (r.checks.isEmpty()) "No collector results recorded." else r.checks.joinToString("\n") { "${it.checkId}: ${it.status} — ${it.summary}" }
        sections += "Findings"
        sections += if (r.findings.isEmpty()) "No findings recorded; this is not a clean bill of health." else r.findings.joinToString("\n\n") { "${it.severity} (${it.confidence}) — ${it.title}\n${it.evidence}\nPrerequisite: ${it.attackerPrerequisite}\nRemediation: ${it.remediation}" }
        sections += "Recent actions"
        sections += if (r.steps.isEmpty()) "No actions recorded." else r.steps.takeLast(10).joinToString("\n") { "#${it.index} ${it.action.kind}: ${it.outcome}" }
        val hypotheses = r.steps.filter { it.action.kind == ActionKind.REPORT_HYPOTHESIS }
        sections += "Model hypotheses — unverified suggestions, not findings"
        sections += if (hypotheses.isEmpty()) "No model hypotheses recorded." else hypotheses.joinToString("\n\n") { "${it.action.text}\nSupporting observation: ${it.action.reason}" }
        report.text = sections.joinToString("\n\n")
    }
    private fun viewEvidence() {
        try {
            val privateRoot = filesDir.canonicalFile
            val candidates = repo.latestSession()?.checks.orEmpty().flatMap { it.artifacts }.distinct().mapNotNull { path ->
                retainedEvidenceFile(java.io.File(path), privateRoot)
            }
            if (candidates.isEmpty()) {
                error("No retained screenshot", "This assessment has no validated screenshot artifact in app-private storage.")
                return
            }
            val titles = candidates.map { it.name }.toTypedArray()
            AlertDialog.Builder(this).setTitle("Choose retained evidence").setItems(titles) { _, index -> showEvidence(candidates[index]) }.setNegativeButton("Cancel", null).show()
        } catch (e: Exception) { error("Evidence unavailable", e.message ?: "The stored assessment could not be read.") }
    }

    private fun showEvidence(file: java.io.File) {
        try {
            val root = filesDir.canonicalFile
            require(retainedEvidenceFile(file, root) != null) { "Evidence file failed app-private path validation." }
            val bounds = android.graphics.BitmapFactory.Options().apply { inJustDecodeBounds = true }
            android.graphics.BitmapFactory.decodeFile(file.path, bounds)
            require(bounds.outWidth in 1..30_000 && bounds.outHeight in 1..30_000) { "Evidence image dimensions are invalid." }
            var sample = 1
            while (bounds.outWidth.toLong() / sample * (bounds.outHeight.toLong() / sample) > 2_000_000L) sample *= 2
            val image = android.graphics.BitmapFactory.decodeFile(file.path, android.graphics.BitmapFactory.Options().apply { inSampleSize = sample })
                ?: throw IllegalStateException("The evidence file is not a readable image.")
            val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(16), dp(8), dp(16), dp(8)) }
            content.addView(fieldLabel("Screenshots may contain sensitive staging data. Review before sharing."))
            content.addView(ImageView(this).apply { setImageBitmap(image); adjustViewBounds = true; scaleType = ImageView.ScaleType.FIT_CENTER; contentDescription = "Retained assessment screenshot" }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(440)))
            AlertDialog.Builder(this).setTitle(file.name).setView(content).setPositiveButton("Close", null).show()
        } catch (e: Exception) { error("Evidence unavailable", e.message ?: "The screenshot could not be safely displayed.") }
    }

    private fun retainedEvidenceFile(file: java.io.File, root: java.io.File): java.io.File? {
        val canonical = file.canonicalFile
        return canonical.takeIf {
            it.path.startsWith(root.path + java.io.File.separator) &&
                file.absolutePath == it.path && it.isFile && it.length() in 1..8_388_608L
        }
    }

    private fun exportReport() { try { val r = repo.latestSession() ?: throw IllegalStateException("No saved report is available yet."); val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).setType("text/markdown").putExtra(Intent.EXTRA_TITLE, "security-assessment-${r.id}.md").addCategory(Intent.CATEGORY_OPENABLE); startActivityForResult(intent, picker + 1) } catch (e: Exception) { error("Export unavailable", e.message ?: "No report is available.") } }
    private fun writeReport(requestCode: Int, resultCode: Int, data: Intent?) { if (requestCode != picker + 1 || resultCode != RESULT_OK || data?.data == null) return; try { val r = repo.latestSession() ?: error("No report is available."); contentResolver.openOutputStream(data.data!!)?.use { out -> OutputStreamWriter(out, Charsets.UTF_8).use { it.write(repo.report(r)) } } ?: error("The document provider did not open the selected file."); Toast.makeText(this, "Markdown report exported.", Toast.LENGTH_LONG).show() } catch (e: Exception) { error("Export failed", e.message ?: "The report could not be written.") } }
    private fun latestSessionId(): String = repo.latestSession()?.id ?: throw IllegalStateException("No assessment session exists yet, so there is no session log.")
    private fun viewLog() {
        try {
            val text = repo.exportLog(latestSessionId())
            val body = TextView(this).apply { this.text = text; textSize = 12f; setTextColor(0xff10243a.toInt()); setTextIsSelectable(true); typeface = android.graphics.Typeface.MONOSPACE; setPadding(dp(16), dp(8), dp(16), dp(8)) }
            AlertDialog.Builder(this).setTitle("Session log").setView(ScrollView(this).apply { addView(body) }).setPositiveButton("Close", null).show()
        } catch (e: Exception) { error("Log unavailable", e.message ?: "The session log could not be read.") }
    }
    private fun exportLog() {
        try {
            val id = latestSessionId(); pendingLogSessionId = id
            startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).setType("text/markdown").putExtra(Intent.EXTRA_TITLE, "security-assessment-log-$id.md").addCategory(Intent.CATEGORY_OPENABLE), picker + 2)
        } catch (e: Exception) { error("Export unavailable", e.message ?: "No session log is available.") }
    }
    private fun writeLog(resultCode: Int, data: Intent?) {
        val id = pendingLogSessionId; pendingLogSessionId = null
        val uri = data?.data
        if (resultCode != RESULT_OK || uri == null || id == null) return
        try {
            contentResolver.openOutputStream(uri)?.use { out -> OutputStreamWriter(out, Charsets.UTF_8).use { it.write(repo.exportLog(id)) } } ?: throw IllegalStateException("The document provider did not open the selected file.")
            Toast.makeText(this, "Session log exported.", Toast.LENGTH_LONG).show()
        } catch (e: Exception) { error("Export failed", e.message ?: "The session log could not be written.") }
    }
    private fun error(title: String, message: String) { AlertDialog.Builder(this).setTitle(title).setMessage(message).setPositiveButton("OK", null).show() }
    override fun onResume() { super.onResume(); refresh(); if (AgentService.isRunning) startPolling() }
    override fun onStop() { polling = false; handler.removeCallbacks(pollTask); super.onStop() }
}
