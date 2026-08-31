from __future__ import annotations

import json
import os
import unittest

from nemos.analyst import (
    Analyst,
    AnalystConfig,
    AnalystUnavailable,
    collect_evidence,
    extract_referenced_facts,
    verify_response,
)

BUNDLE = {
    "incident": {"incident_id": "NEMOS-ABC123", "risk_score": 88},
    "alerts": [{
        "threat": "PORT_SCAN", "source": "192.0.2.10", "technique": "T1046",
        "reason": "259 unique destination ports in 10s", "risk_score": 88,
    }],
    "flows": [{"source": "192.0.2.10", "destination": "198.51.100.50",
               "protocol": "TCP", "packets": 4}],
}


def configured(transport):
    return Analyst(
        AnalystConfig(provider="anthropic", model="test-model", api_key="k" * 20,
                      base_url="https://api.anthropic.com/v1/messages"),
        transport=transport,
    )


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.copy()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._saved)

    def test_unconfigured_by_default(self):
        os.environ.pop("NEMOS_LLM_PROVIDER", None)
        self.assertFalse(AnalystConfig.from_env().configured)

    def test_unknown_provider_is_rejected(self):
        os.environ["NEMOS_LLM_PROVIDER"] = "definitely-not-a-provider"
        self.assertFalse(AnalystConfig.from_env().configured)

    def test_missing_api_key_disables_the_analyst(self):
        os.environ["NEMOS_LLM_PROVIDER"] = "anthropic"
        os.environ.pop("ANTHROPIC_API_KEY", None)
        self.assertFalse(AnalystConfig.from_env().configured)

    def test_configured_with_provider_and_key(self):
        os.environ["NEMOS_LLM_PROVIDER"] = "anthropic"
        os.environ["ANTHROPIC_API_KEY"] = "test-key-value"
        config = AnalystConfig.from_env()
        self.assertTrue(config.configured)
        self.assertEqual(config.provider, "anthropic")

    def test_hosted_provider_endpoint_cannot_be_redirected(self):
        """Evidence describes the monitored network; it must not be retargeted."""
        os.environ["NEMOS_LLM_PROVIDER"] = "anthropic"
        os.environ["ANTHROPIC_API_KEY"] = "test-key-value"
        os.environ["NEMOS_LLM_URL"] = "https://evil.example.net/collect"
        self.assertFalse(AnalystConfig.from_env().configured)

    def test_ollama_must_be_loopback(self):
        os.environ["NEMOS_LLM_PROVIDER"] = "ollama"
        os.environ["NEMOS_LLM_URL"] = "http://192.0.2.50:11434/api/chat"
        self.assertFalse(AnalystConfig.from_env().configured)

    def test_ollama_loopback_is_accepted(self):
        os.environ["NEMOS_LLM_PROVIDER"] = "ollama"
        os.environ["NEMOS_LLM_URL"] = "http://127.0.0.1:11434/api/chat"
        self.assertTrue(AnalystConfig.from_env().configured)


class UnavailableTests(unittest.TestCase):
    def test_explain_raises_when_unconfigured(self):
        with self.assertRaises(AnalystUnavailable):
            Analyst(AnalystConfig()).explain("why?", BUNDLE)

    def test_status_explains_absence_without_calling_it_an_error(self):
        status = Analyst(AnalystConfig()).status()
        self.assertFalse(status["available"])
        self.assertIn("detection is unaffected", status["reason"])
        json.dumps(status)


class EvidenceTests(unittest.TestCase):
    def test_bundle_contains_only_supplied_facts(self):
        bundle = collect_evidence(incident={"incident_id": "X"}, alerts=[{"threat": "Y"}])
        self.assertIn("incident", bundle)
        self.assertIn("alerts", bundle)
        self.assertNotIn("flows", bundle)

    def test_flows_are_truncated_and_the_truncation_is_stated(self):
        bundle = collect_evidence(flows=[{"source": f"10.0.0.{i}"} for i in range(200)])
        self.assertEqual(len(bundle["flows"]), 40)
        self.assertIn("of 200", bundle["flow_note"])

    def test_extract_finds_addresses_and_techniques(self):
        addresses, techniques = extract_referenced_facts(BUNDLE)
        self.assertIn("192.0.2.10", addresses)
        self.assertIn("198.51.100.50", addresses)
        self.assertIn("T1046", techniques)


class VerificationTests(unittest.TestCase):
    """The response is inspected, not trusted."""

    def test_faithful_response_passes(self):
        ok, problems = verify_response(
            "Host 192.0.2.10 scanned 198.51.100.50; this is consistent with T1046.", BUNDLE)
        self.assertTrue(ok, problems)

    def test_invented_ip_is_caught(self):
        ok, problems = verify_response("The attacker at 203.0.113.99 was involved.", BUNDLE)
        self.assertFalse(ok)
        self.assertIn("203.0.113.99", problems[0])

    def test_invented_technique_is_caught(self):
        ok, problems = verify_response("This maps to T1566 phishing.", BUNDLE)
        self.assertFalse(ok)
        self.assertIn("T1566", problems[0])

    def test_prose_without_facts_passes(self):
        ok, _ = verify_response("The evidence is insufficient to determine intent.", BUNDLE)
        self.assertTrue(ok)

    def test_version_numbers_are_not_mistaken_for_addresses(self):
        ok, _ = verify_response("Confidence was high across the window.", BUNDLE)
        self.assertTrue(ok)


class ExplainTests(unittest.TestCase):
    def test_faithful_answer_is_returned(self):
        analyst = configured(lambda prompt, config: "Host 192.0.2.10 performed a scan (T1046).")
        result = analyst.explain("what happened?", BUNDLE)
        self.assertTrue(result["ok"])
        self.assertTrue(result["verified"])
        self.assertIn("disclaimer", result)

    def test_hallucinated_answer_is_rejected_not_shown(self):
        analyst = configured(lambda prompt, config: "Host 203.0.113.7 dropped Emotet malware.")
        result = analyst.explain("what happened?", BUNDLE)
        self.assertFalse(result["ok"])
        self.assertNotIn("answer", result)
        self.assertEqual(analyst.status()["rejected_for_unverifiable_claims"], 1)

    def test_provider_failure_is_structured_not_raised(self):
        def broken(prompt, config):
            raise RuntimeError("connection refused")

        result = configured(broken).explain("why?", BUNDLE)
        self.assertFalse(result["ok"])
        self.assertIn("unaffected", result["note"])

    def test_api_key_is_redacted_from_errors(self):
        key = "k" * 20

        def leaky(prompt, config):
            raise RuntimeError(f"auth failed for {key}")

        analyst = configured(leaky)
        result = analyst.explain("why?", BUNDLE)
        self.assertNotIn(key, json.dumps(result))
        self.assertNotIn(key, json.dumps(analyst.status()))

    def test_oversized_bundle_is_refused(self):
        analyst = configured(lambda prompt, config: "ok")
        huge = {"flows": [{"source": "10.0.0.1", "note": "x" * 100} for _ in range(1000)]}
        result = analyst.explain("summarise", huge)
        self.assertFalse(result["ok"])
        self.assertIn("too large", result["error"])

    def test_prompt_carries_the_evidence_and_the_question(self):
        captured = {}

        def capture(prompt, config):
            captured["prompt"] = prompt
            return "The evidence is insufficient."

        configured(capture).explain("why is this host suspicious?", BUNDLE)
        self.assertIn("192.0.2.10", captured["prompt"])
        self.assertIn("why is this host suspicious?", captured["prompt"])
        self.assertIn("only", captured["prompt"].lower())

    def test_response_is_length_capped(self):
        analyst = configured(lambda prompt, config: "word " * 5000)
        result = analyst.explain("summarise", BUNDLE)
        self.assertTrue(result["ok"])
        self.assertLessEqual(len(result["answer"]), 4000)

    def test_counters_track_usage(self):
        analyst = configured(lambda prompt, config: "Nothing conclusive.")
        analyst.explain("a", BUNDLE)
        analyst.explain("b", BUNDLE)
        self.assertEqual(analyst.status()["requests"], 2)
        self.assertEqual(analyst.status()["failures"], 0)


class SystemPromptTests(unittest.TestCase):
    def test_prompt_forbids_invention_and_overclaiming(self):
        from nemos.analyst import SYSTEM_PROMPT

        lowered = SYSTEM_PROMPT.lower()
        self.assertIn("never invent", lowered)
        self.assertIn("insufficient", lowered)
        self.assertIn("not a probability", lowered)
        self.assertIn("investigation steps, never containment", lowered)


if __name__ == "__main__":
    unittest.main()
