package policybundle

import (
	"bytes"
	"testing"

	"github.com/Fhwang0926/m-waf/internal/systempolicy"
)

func TestBuildIsDeterministicAndParseVerifiesFiles(t *testing.T) {
	source := systempolicy.PolicySourceRef{ID: "owasp-crs-4.28.0", Repository: "https://github.com/coreruleset/coreruleset", Tag: "v4.28.0", Commit: "0123456789abcdef", ArchiveSHA256: repeatHex("a"), IndexSHA256: repeatHex("b")}
	input := Input{Mode: "DetectionOnly", RequestBody: true, CRSSetup: map[string]string{"blocking_paranoia_level": "1", "inbound_anomaly_score_threshold": "5"}, After: []systempolicy.RuleExclusion{{RuleID: 942100}}}
	first, manifest, err := Build(source, input)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := Build(source, input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("policy bundle must be deterministic")
	}
	parsed, files, err := Parse(first)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.PolicySource.ID != source.ID || len(manifest.Files) != 6 || !bytes.Contains(files["50-after-crs-exclusions.conf"], []byte("SecRuleRemoveById 942100")) {
		t.Fatalf("unexpected parsed bundle: %#v", parsed)
	}
	tampered := append([]byte(nil), first...)
	tampered[len(tampered)/2] ^= 0xff
	if _, _, err := Parse(tampered); err == nil {
		t.Fatal("tampered policy bundle must be rejected")
	}
}

func TestBuildWithCRSCarriesImmutableSourceFiles(t *testing.T) {
	source := systempolicy.PolicySourceRef{ID: "owasp-crs-4.28.0", Repository: "https://github.com/coreruleset/coreruleset", Tag: "v4.28.0", Commit: "0123456789abcdef", ArchiveSHA256: repeatHex("a"), IndexSHA256: repeatHex("b")}
	input := Input{Mode: "DetectionOnly", RequestBody: true, CRSSetup: map[string]string{"blocking_paranoia_level": "1"}}
	raw, manifest, err := BuildWithCRS(source, input, map[string][]byte{
		"crs/crs-setup.conf": []byte("# upstream setup\n"),
		"crs/rules/a.conf":   []byte("SecAction \"id:900001,phase:1,pass\"\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := BuildWithCRS(source, input, map[string][]byte{
		"crs/crs-setup.conf": []byte("# upstream setup\n"),
		"crs/rules/a.conf":   []byte("SecAction \"id:900001,phase:1,pass\"\n"),
	})
	if err != nil || !bytes.Equal(raw, second) {
		t.Fatal("the same v3 snapshot must create byte-identical bundles")
	}
	parsed, files, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ArtifactFormat != FormatV3 || parsed.SchemaVersion != 3 || !bytes.Equal(files["crs/rules/a.conf"], []byte("SecAction \"id:900001,phase:1,pass\"\n")) {
		t.Fatalf("unexpected self-contained policy: %#v", parsed)
	}
	if !bytes.Contains(files["40-crs-rules.conf"], []byte("/etc/mwaf/active/crs/rules/*.conf")) {
		t.Fatal("self-contained policy must load CRS from the active revision")
	}
}

func TestBaseAndEnterpriseOverrideRemainSeparateAndPinned(t *testing.T) {
	source := systempolicy.PolicySourceRef{ID: "owasp-crs-4.28.0", Repository: "https://github.com/coreruleset/coreruleset", Tag: "v4.28.0", Commit: "0123456789abcdef", ArchiveSHA256: repeatHex("a"), IndexSHA256: repeatHex("b")}
	baseRaw, _, err := BuildBaseWithCRS("system-policy-4.28.0", source, Input{
		Mode: "DetectionOnly", RequestBody: true, CRSSetup: map[string]string{"blocking_paranoia_level": "1"},
	}, map[string][]byte{
		"crs/crs-setup.conf": []byte("# upstream setup\n"),
		"crs/rules/a.conf":   []byte("SecAction \"id:900001,phase:1,pass\"\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	baseHash := repeatHex("c")
	overrideRaw, _, err := BuildOverride(source, OverrideInput{
		IncludeScalars: true, Mode: "On", RequestBody: true,
		CRSSetup:    map[string]string{"blocking_paranoia_level": "2"},
		CustomRules: []CustomRule{{RuleID: 40000, Scope: "ENTERPRISE", Canonical: `SecRule REQUEST_URI "@streq /private" "id:40000,phase:2,deny"`, Enabled: true}},
	}, OverrideMetadata{
		BasePolicyID: "system-policy-4.28.0", BaseArtifactSHA256: baseHash,
		OverrideConfigSHA256: repeatHex("d"), EffectiveConfigSHA256: repeatHex("e"), ValidationDigest: repeatHex("f"),
	})
	if err != nil {
		t.Fatal(err)
	}
	baseManifest, baseFiles, err := Parse(baseRaw)
	if err != nil {
		t.Fatal(err)
	}
	overrideManifest, overrideFiles, err := Parse(overrideRaw)
	if err != nil {
		t.Fatal(err)
	}
	if baseManifest.ArtifactFormat != FormatBase || overrideManifest.ArtifactFormat != FormatOverride || overrideManifest.BaseArtifactSHA256 != baseHash {
		t.Fatalf("unexpected split manifests: %#v %#v", baseManifest, overrideManifest)
	}
	if baseFiles["40-base-crs-rules.conf"] == nil || baseFiles["65-enterprise-service-rules.conf"] != nil || !bytes.Contains(overrideFiles["65-enterprise-service-rules.conf"], []byte("id:40000")) || overrideFiles["crs/rules/a.conf"] != nil {
		t.Fatalf("base and override contents were not separated: base=%#v override=%#v", baseFiles, overrideFiles)
	}
}

func TestStructuredExclusionsRenderBeforeAndAfterCRS(t *testing.T) {
	source := systempolicy.PolicySourceRef{ID: "owasp-crs-stable", Commit: "0123456789abcdef", IndexSHA256: repeatHex("b")}
	input := Input{
		Mode: "On", RequestBody: true, ResponseBody: true,
		CRSSetup: map[string]string{"blocking_paranoia_level": "1", "detection_paranoia_level": "2"},
		Exclusions: []Exclusion{
			{Type: "RULE", LoadStage: "BEFORE_CRS", RuleID: 942100, GeneratedRuleID: 5000, Enabled: true, Conditions: []Condition{{Field: "REQUEST_URI", Operator: "@beginsWith", Value: "/health"}}},
			{Type: "TARGET", LoadStage: "BEFORE_CRS", RuleID: 942100, Target: "ARGS:password", GeneratedRuleID: 5001, Enabled: true, Conditions: []Condition{{Field: "REQUEST_URI", Operator: "@streq", Value: "/login"}}},
			{Type: "RULE", LoadStage: "AFTER_CRS", RuleID: 932100, Enabled: true},
			{Type: "TAG", LoadStage: "AFTER_CRS", RuleTag: "attack-sqli", Enabled: true},
		},
		CustomRules: []CustomRule{{RuleID: 40000, Scope: "ENTERPRISE", Canonical: `SecRule REQUEST_URI "@streq /private" "id:40000,phase:2,deny"`, Enabled: true}},
	}
	raw, _, err := Build(source, input)
	if err != nil {
		t.Fatal(err)
	}
	_, files, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(files["00-engine.conf"], []byte("SecResponseBodyAccess On")) ||
		!bytes.Contains(files["30-before-crs-exclusions.conf"], []byte("ctl:ruleRemoveById=942100")) ||
		!bytes.Contains(files["30-before-crs-exclusions.conf"], []byte("ctl:ruleRemoveTargetById=942100;ARGS:password")) ||
		!bytes.Contains(files["50-after-crs-exclusions.conf"], []byte("SecRuleRemoveById 932100")) ||
		!bytes.Contains(files["50-after-crs-exclusions.conf"], []byte("SecRuleRemoveByTag attack-sqli")) ||
		!bytes.Contains(files["60-service-rules.conf"], []byte("id:40000")) {
		t.Fatalf("structured policy files were rendered in the wrong stage: %#v", files)
	}
}

func TestIPRulesRenderBeforeCRS(t *testing.T) {
	source := systempolicy.PolicySourceRef{ID: "owasp-crs-lts", Commit: "0123456789abcdef", IndexSHA256: repeatHex("b")}
	raw, _, err := Build(source, Input{
		Mode: "On", RequestBody: true,
		IPRules: []IPRule{
			{Action: "BLOCK", Network: "192.0.2.10/32", GeneratedRuleID: 5000, Enabled: true},
			{Action: "TRUST", Network: "2001:db8::/48", GeneratedRuleID: 5001, Enabled: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, files, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	before := files["30-before-crs-exclusions.conf"]
	if !bytes.Contains(before, []byte(`@ipMatch 192.0.2.10/32`)) || !bytes.Contains(before, []byte(`deny,status:403`)) {
		t.Fatalf("BLOCK Rule was not rendered before CRS: %s", before)
	}
	if !bytes.Contains(before, []byte(`@ipMatch 2001:db8::/48`)) || !bytes.Contains(before, []byte(`ctl:ruleEngine=Off`)) {
		t.Fatalf("TRUST Rule was not rendered before CRS: %s", before)
	}
}

func TestRenderSetupKeepsUnlimitedAsUpstreamInheritance(t *testing.T) {
	rendered := renderSetup(map[string]string{
		"blocking_paranoia_level": "1",
		"max_file_size":           "unlimited",
		"combined_file_sizes":     "UNLIMITED",
	})
	if bytes.Contains([]byte(rendered), []byte("max_file_size")) || bytes.Contains([]byte(rendered), []byte("combined_file_sizes")) {
		t.Fatalf("unlimited values must not create invalid setvar overrides: %s", rendered)
	}
	if !bytes.Contains([]byte(rendered), []byte("blocking_paranoia_level=1")) {
		t.Fatalf("numeric setup override was omitted: %s", rendered)
	}
}

func repeatHex(value string) string {
	var output bytes.Buffer
	for output.Len() < 64 {
		output.WriteString(value)
	}
	return output.String()
}
