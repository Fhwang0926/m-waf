package crsindex

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func TestBuildFromArchiveIndexesMultilineAndChainRules(t *testing.T) {
	archive := testArchive(t, map[string]string{
		"coreruleset-4.28.0/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf": `
SecRule ARGS|ARGS_NAMES "@rx select" \
    "id:942100,phase:2,deny,severity:'CRITICAL',msg:'SQL injection',tag:'attack-sqli',tag:'paranoia-level/1'"
SecRule REQUEST_URI "@beginsWith /admin" "id:949001,phase:1,pass,chain,tag:'paranoia-level/2'"
    SecRule REQUEST_METHOD "@streq POST" "deny,severity:'WARNING',msg:'Admin POST'"
`,
	})
	index, err := BuildFromArchive(bytes.NewReader(archive), testSource())
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Rules) != 2 || index.Rules[0].ID != 942100 || index.Rules[0].Line != 2 {
		t.Fatalf("unexpected indexed rules: %#v", index.Rules)
	}
	if index.Rules[1].ID != 949001 || index.Rules[1].ParanoiaLevel != 2 || index.Rules[1].Directive == "" {
		t.Fatalf("unexpected chained rule: %#v", index.Rules[1])
	}
}

func TestBuildFromArchiveRejectsDuplicateRuleID(t *testing.T) {
	archive := testArchive(t, map[string]string{
		"coreruleset-4.28.0/rules/a.conf": `SecAction "id:900001,phase:1,pass"`,
		"coreruleset-4.28.0/rules/b.conf": `SecAction "id:900001,phase:1,pass"`,
	})
	if _, err := BuildFromArchive(bytes.NewReader(archive), testSource()); err == nil {
		t.Fatal("expected duplicate Rule ID rejection")
	}
}

func TestPolicyFilesFromArchivePreservesRulesAndData(t *testing.T) {
	archive := testArchive(t, map[string]string{
		"coreruleset-4.28.0/rules/a.conf": `SecAction "id:900001,phase:1,pass"`,
		"coreruleset-4.28.0/rules/a.data": "one\ntwo\n",
	})
	files, err := PolicyFilesFromArchive(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	if string(files["crs/rules/a.data"]) != "one\ntwo\n" || len(files["crs/crs-setup.conf"]) == 0 {
		t.Fatalf("unexpected CRS policy files: %#v", files)
	}
}

func TestBuildFromArchiveIndexesCompleteSourceInventory(t *testing.T) {
	archive := testArchive(t, map[string]string{
		"coreruleset-4.28.0/crs-setup.conf.example": strings.Join([]string{
			setupExampleForSupportedFields(),
			"# setvar:tx.reporting_level=4\"",
		}, "\n"),
		"coreruleset-4.28.0/rules/a.conf": strings.Join([]string{
			`SecRule ARGS "@pmFromFile keywords.data" "id:900001,phase:1,pass"`,
			`SecRuleUpdateTargetById 900001 "!ARGS:ignored"`,
			`SecMarker "END-A"`,
		}, "\n"),
		"coreruleset-4.28.0/rules/keywords.data": "one\ntwo\n",
	})
	index, err := BuildFromArchive(bytes.NewReader(archive), testSource())
	if err != nil {
		t.Fatal(err)
	}
	if index.Statistics.TotalFileCount != 3 || index.Statistics.DataFileCount != 1 || index.Statistics.DirectiveCount != 2 {
		t.Fatalf("unexpected inventory statistics: %#v", index.Statistics)
	}
	if len(index.SourceSetup) != len(SupportedSetup())+1 || index.Statistics.SetupKeyCount != len(index.SourceSetup) {
		t.Fatalf("complete setup inventory was not indexed: %#v", index.SourceSetup)
	}
	var data SourceFile
	for _, file := range index.Files {
		if file.Path == "rules/keywords.data" {
			data = file
		}
	}
	if data.SHA256 == "" || len(data.ReferencedBy) != 1 || data.ReferencedBy[0] != 900001 {
		t.Fatalf("data file reference was not indexed: %#v", data)
	}
}

func TestSupportedSetupFromExampleDoesNotPromoteCommentedExamplesToDefaults(t *testing.T) {
	var setup strings.Builder
	for _, field := range SupportedSetup() {
		value := field.Default
		switch field.Key {
		case "early_blocking":
			value = "1"
		case "max_file_size", "combined_file_sizes":
			value = "1048576"
		}
		setup.WriteString("# setvar:tx.")
		setup.WriteString(field.Key)
		setup.WriteString("=")
		setup.WriteString(value)
		setup.WriteByte('\n')
	}
	fields, err := SupportedSetupFromExample(setup.String())
	if err != nil {
		t.Fatal(err)
	}
	defaults := make(map[string]string, len(fields))
	for _, field := range fields {
		defaults[field.Key] = field.Default
	}
	if defaults["early_blocking"] != "0" || defaults["max_file_size"] != "unlimited" || defaults["combined_file_sizes"] != "unlimited" {
		t.Fatalf("commented examples changed reviewed defaults: %#v", defaults)
	}
}

func testSource() Source {
	return Source{Provider: "github", Repository: "https://github.com/coreruleset/coreruleset", Channel: "stable", Version: "4.28.0", Tag: "v4.28.0", Commit: "0123456789abcdef", ArchiveSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
}

func setupExampleForSupportedFields() string {
	var setup strings.Builder
	for _, field := range SupportedSetup() {
		setup.WriteString("# setvar:tx.")
		setup.WriteString(field.Key)
		setup.WriteString("=")
		setup.WriteString(field.Default)
		setup.WriteString("\"\n")
	}
	return setup.String()
}

func testArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	if _, ok := files["coreruleset-4.28.0/crs-setup.conf.example"]; !ok {
		var setup strings.Builder
		for _, field := range SupportedSetup() {
			setup.WriteString("# setvar:tx.")
			setup.WriteString(field.Key)
			setup.WriteString("=")
			setup.WriteString(field.Default)
			setup.WriteByte('\n')
		}
		files["coreruleset-4.28.0/crs-setup.conf.example"] = setup.String()
	}
	var output bytes.Buffer
	compressor := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressor)
	for name, content := range files {
		if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
