package com.mekari.securityagent
import org.json.JSONObject
import org.junit.Assert.*

import org.junit.Test

class RuntimeCoreBehaviorTest {
    private val config = SessionConfig("com.example.target","https://api.example.test/v1/chat/completions","chosen-model",listOf("staging.example.test"),cloudConsent=true)
    private val fresh = Observation(config.targetPackage,listOf(UiNode("btn",packageName=config.targetPackage,clickable=true),UiNode("pw",packageName=config.targetPackage,editable=true,password=true)),System.currentTimeMillis())

    @Test fun liveAdvisoryEndpointIsValidatedAgainstTheToggle() {
        assertNull(ActionPolicy.validateConfig(config.copy(liveAdvisories = true, advisoryEndpoint = "https://feeds.example.test/mobile?since=2026")))
        assertNotNull(ActionPolicy.validateConfig(config.copy(liveAdvisories = true, advisoryEndpoint = "http://feeds.example.test/mobile")))
        assertNotNull(ActionPolicy.validateConfig(config.copy(liveAdvisories = true, advisoryEndpoint = "")))
        assertNotNull(ActionPolicy.validateConfig(config.copy(liveAdvisories = false, advisoryEndpoint = "https://feeds.example.test/mobile")))
        assertNull(ActionPolicy.validateConfig(config.copy(liveAdvisories = false, advisoryEndpoint = "")))
    }
    @Test fun persistedValidatorToleratesNewOptionalConfigKeysButRejectsUnknown() {
        fun configJson() = JSONObject().put("targetPackage","com.example.target").put("endpoint","https://api.example.test/v1/chat/completions").put("model","m").put("allowedHosts",org.json.JSONArray(listOf("staging.example.test"))).put("maxSteps",10).put("screenshotsToCloud",false).put("cloudConsent",true)
        fun record(cfg: JSONObject) = JSONObject().put("id","s").put("config",cfg).put("status","READY").put("startedAt",1L).put("updatedAt",1L).put("message","m").put("steps",org.json.JSONArray()).put("checks",org.json.JSONArray()).put("findings",org.json.JSONArray()).put("visitedScreens",org.json.JSONArray()).toString()
        PersistedRecordValidator.validate(record(configJson()), "s") // legacy config without the new keys
        PersistedRecordValidator.validate(record(configJson().put("provider","ANTHROPIC").put("liveAdvisories",true).put("advisoryEndpoint","https://f.example.test/a")), "s")
        try { PersistedRecordValidator.validate(record(configJson().put("unexpected","x")), "s"); fail("accepted unknown key") } catch (_: Exception) {}
        try { PersistedRecordValidator.validate(record(configJson().put("provider","NOT_A_PROVIDER")), "s"); fail("accepted bad provider") } catch (_: Exception) {}
    }
    @Test fun rejectsWrongPackageStaleAndOutOfScopeNodes() {
        assertFalse(ActionPolicy.validate(AgentAction(ActionKind.TAP,"btn"),fresh.copy(packageName="other.app"),config).accepted)
        assertFalse(ActionPolicy.validate(AgentAction(ActionKind.TAP,"btn"),fresh.copy(capturedAt=0),config).accepted)
        assertFalse(ActionPolicy.validate(AgentAction(ActionKind.TAP,"other"),fresh,config).accepted)
    }
    @Test fun rejectsUnsafeOrIrrelevantActions() {
        assertFalse(ActionPolicy.validate(AgentAction(ActionKind.TYPE_TEXT,"pw",text="x"),fresh,config).accepted)
        assertFalse(ActionPolicy.validate(AgentAction(ActionKind.RUN_CHECK,checkId="shell"),fresh,config).accepted)
        assertFalse(ActionPolicy.validate(AgentAction(ActionKind.BACK,reason="unneeded"),fresh,config).accepted)
    }
    @Test fun hypothesisActionRequiresBothUnverifiedClaimAndSupport() {
        assertTrue(ActionPolicy.validate(AgentAction(ActionKind.REPORT_HYPOTHESIS, text="possible issue", reason="observed staging evidence"), fresh, config).accepted)
        assertFalse(ActionPolicy.validate(AgentAction(ActionKind.REPORT_HYPOTHESIS, text="possible issue"), fresh, config).accepted)
    }
    @Test fun credentialReferencesMustMatchPasswordNodeType() {
        assertTrue(ActionPolicy.validate(AgentAction(ActionKind.ENTER_CREDENTIAL, "pw", credentialId="password"), fresh, config).accepted)
        assertFalse(ActionPolicy.validate(AgentAction(ActionKind.ENTER_CREDENTIAL, "pw", credentialId="username"), fresh, config).accepted)
    }
    @Test fun decodesOnlyClosedActionVocabulary() {
        assertEquals(ActionKind.TAP,CloudModelClient.decodeAction("{\"kind\":\"TAP\",\"nodeId\":\"btn\"}").kind)
        for (input in listOf(
            "{}",
            "{\"kind\":\"RUN_SHELL\"}",
            "{\"kind\":\"TAP\",\"extra\":\"value\"}",
            "{\"kind\":\"TAP\",\"nodeId\":{}}",
            "{\"kind\":\"TAP\",\"kind\":\"BACK\"}",
            "{'kind':'TAP'}",
            "{\"kind\":\"WAIT\",\"reason\":1000}",
            "{\"kind\":\"TAP\"} trailing"
        )) {
            try { CloudModelClient.decodeAction(input); fail("accepted $input") } catch (_: Exception) { }
        }
    }
    @Test fun redactsCredentialFromEveryObservationFieldAndActionReason() {
        val secret = "uniqueSecretValue"
        val input = fresh.copy(nodes=listOf(UiNode("x",text=secret,description=secret,resourceId=secret,bounds=secret,packageName=config.targetPackage)))
        val clean = Redactor.sanitizeObservation(input,listOf(secret))
        clean.nodes.single().let { assertFalse(it.text.contains(secret)); assertFalse(it.description.contains(secret)); assertFalse(it.resourceId.contains(secret)); assertFalse(it.bounds.contains(secret)) }
        assertFalse(Redactor.sanitizeAction(AgentAction(ActionKind.REQUEST_HELP,reason=secret),listOf(secret)).reason.contains(secret))
    }
    @Test fun sanitizedRecordKeepsAppGeneratedArtifactPathsResolvable() {
        // UUID segment 9745-4153053 matches the generic phone-number pattern; app-generated paths must survive it.
        val path = "/data/user/0/com.mekari.securityagent/files/assessment-screenshots/76b8d301-33b7-4d2e-9745-4153053b56d5.png"
        val secret = "uniqueSecretValue"
        val record = SessionRecord("s",config,checks=listOf(CheckResult("screenshots","complete","ok",artifacts=listOf(path,"/x/$secret.png"))))
        val artifacts = Redactor.sanitizeRecord(record,listOf(secret)).checks.single().artifacts
        assertEquals(path, artifacts[0])
        assertFalse(artifacts[1].contains(secret))
    }
    @Test fun markdownEscapesUntrustedHtmlText() {
        val r=SessionRecord("s",config,findings=listOf(Finding("f","<script>|x","high","low","evidence","prereq","fix")))
        val report=ReportRenderer.render(r)
        assertFalse(report.contains("<script>")); assertTrue(report.contains("&lt;script&gt;"))
    }
    @Test fun exportedRecordKeepsHypothesesUnverifiedAndSeparateFromFindings() {
        val summary = "Possible storage exposure"
        val evidence = "A non-sensitive path label appeared"
        val hypothesis = AgentAction(ActionKind.REPORT_HYPOTHESIS, text=summary, reason=evidence)
        val record = SessionRecord("s", config, steps=listOf(StepRecord(1, 1, hypothesis, config.targetPackage, "Unverified model hypothesis", true)))
        val report = ReportRenderer.render(record)
        val json = Regex("""```json\s*(\{.*?\})\s*```""", RegexOption.DOT_MATCHES_ALL)
            .find(report)!!.groupValues[1]
        val exported = JSONObject(json)
        assertEquals(0, exported.getJSONArray("findings").length())
        val hypotheses = exported.getJSONArray("hypotheses")
        assertEquals(1, hypotheses.length())
        val exportedHypothesis = hypotheses.getJSONObject(0)
        assertEquals("unverified", exportedHypothesis.getString("status"))
        assertEquals(summary, exportedHypothesis.getString("summary"))
        assertEquals(evidence, exportedHypothesis.getString("supportingObservation"))
    }
    @Test fun persistedRecordValidatorRejectsMalformedAndMismatchedRecords() {
        for (raw in listOf("not-json", "{}", """{"id":"other","config":{"targetPackage":"com.example.target","endpoint":"https://api.example.test","model":"model","allowedHosts":[],"maxSteps":1,"screenshotsToCloud":false,"cloudConsent":false},"status":"READY","startedAt":1,"updatedAt":1,"message":"Ready","steps":[],"checks":[],"findings":[],"visitedScreens":[]}""")) {
            try { PersistedRecordValidator.validate(raw, "session"); fail("accepted corrupt or mismatched persisted state") } catch (_: Exception) { }
        }
        val valid = """{"id":"session","config":{"targetPackage":"com.example.target","endpoint":"https://api.example.test/v1/chat/completions","model":"selected","allowedHosts":["staging.example.test"],"maxSteps":1,"screenshotsToCloud":false,"cloudConsent":true},"status":"READY","startedAt":1,"updatedAt":1,"message":"Ready","steps":[],"checks":[],"findings":[],"visitedScreens":[]}"""
        PersistedRecordValidator.validate(valid, "session")
    }
}
