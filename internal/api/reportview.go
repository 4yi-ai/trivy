package api

import (
	"sort"
	"strings"

	"github.com/4yi-ai/codescan/internal/store"
)

// This file builds the view-model for the web scan page: the category x severity
// stats table and the type-based priority tiers. It mirrors the PDF layout
// (drawStatsTable + priority tiers in pdf.go) so the web and PDF reports tell the
// same story. tierOf/isCustomRule/sevRank are shared from pdf.go.

// StatsRow is one row of the category x severity count table.
type StatsRow struct {
	Label                           string
	Crit, High, Med, Low, Info, Tot int
}

// TierGroup is one rendered priority tier (P1..P4) with its findings.
type TierGroup struct {
	Num      int
	Label    string
	Subtitle string
	Class    string // css suffix: p1..p4
	Findings []store.Finding
}

// webTiers is the display metadata for the 4 priority tiers, in order. Labels are
// Chinese here (HTML, not the Latin-1 PDF), matching how the app is used.
var webTiers = []struct{ label, subtitle, class string }{
	{"P1 · 代码漏洞（已验证）", "CodeScan 自定义规则查出的越权 / SQL 注入 / SSRF —— 优先修复", "p1"},
	{"P2 · 直接依赖", "你自己声明的包，升版本即可修复。按严重度排序", "p2"},
	{"P3 · 配置 & 密钥", "IaC 配置、泄露密钥、通用代码坏味道", "p3"},
	{"P4 · 传递依赖", "被其它包间接带入 —— 通常升父包后自动修复。按严重度排序", "p4"},
}

// buildStats returns the category x severity table rows (only categories that
// have findings), in a fixed display order.
func buildStats(findings []store.Finding) []StatsRow {
	rows := []struct{ key, label string }{
		{"sca", "SCA（依赖）"},
		{"sast", "SAST（代码）"},
		{"iac", "IaC（配置）"},
		{"secret", "Secret（密钥）"},
	}
	counts := map[string]map[string]int{}
	for i := range findings {
		cat := strings.ToLower(findings[i].Category)
		if counts[cat] == nil {
			counts[cat] = map[string]int{}
		}
		counts[cat][strings.ToLower(findings[i].Severity)]++
	}
	var out []StatsRow
	for _, r := range rows {
		cc := counts[r.key]
		if cc == nil {
			continue
		}
		row := StatsRow{Label: r.label,
			Crit: cc["critical"], High: cc["high"], Med: cc["medium"],
			Low: cc["low"], Info: cc["info"]}
		row.Tot = row.Crit + row.High + row.Med + row.Low + row.Info
		out = append(out, row)
	}
	return out
}

// buildTiers buckets findings into the 4 priority tiers (most actionable first),
// each sorted by severity. Empty tiers are omitted.
func buildTiers(findings []store.Finding) []TierGroup {
	buckets := map[int][]store.Finding{}
	for _, f := range findings {
		t := tierOf(&f)
		buckets[t] = append(buckets[t], f)
	}
	var out []TierGroup
	for i, meta := range webTiers {
		fs := buckets[i+1]
		if len(fs) == 0 {
			continue
		}
		sort.SliceStable(fs, func(a, b int) bool {
			return sevRank(fs[a].Severity) < sevRank(fs[b].Severity)
		})
		out = append(out, TierGroup{
			Num: i + 1, Label: meta.label, Subtitle: meta.subtitle,
			Class: meta.class, Findings: fs,
		})
	}
	return out
}
