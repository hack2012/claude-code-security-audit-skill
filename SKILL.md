---
name: security-audit
description: Full-stack security audit for Vercel + Supabase + Next.js + iOS. OWASP Top 10:2025, WSTG, MASTG/MASVS v2 compliant. Combines CLI/SQL automated checks with Chrome MCP dashboard inspection for end-to-end security coverage. Triggered by "security audit", "vulnerability scan", or "pentest".
---

# Security Audit

Full-stack vulnerability assessment skill targeting Vercel + Supabase + Next.js + iOS.
Combines codebase static analysis, CLI/SQL configuration checks, and Chrome MCP dashboard inspection to audit all layers end-to-end.

## Design Principles

- **Evidence-First**: Findings backed by code evidence, not speculation
- **Full-Stack Coverage**: Application -> Infrastructure -> Backend -> Mobile
- **Progressive Disclosure**: Scan high-risk areas first, drill down incrementally
- **CLI + Chrome MCP**: Automate what CLI/API can reach; use Chrome MCP for dashboard-only settings

## Target Selection

```
/security-audit              -> Interactive target selection
/security-audit all          -> Full-stack end-to-end audit (recommended)
/security-audit nextjs       -> Next.js application only
/security-audit vercel       -> Vercel infrastructure only
/security-audit supabase     -> Supabase backend only
/security-audit ios          -> iOS app only
/security-audit web          -> Next.js + Vercel + Supabase (full web stack)
```

## Phase 1: Reconnaissance

Understand the target codebase structure.

1. Project composition (framework, language, dependencies, versions)
2. Entry point enumeration (API Routes, Server Actions, URL schemes)
3. Trust boundary identification (user input -> app -> backend -> mobile)
4. Authentication/authorization flow mapping
5. Data flow visualization (sensitive data lifecycle)

## Phase 2: Next.js Application Audit

See `references/nextjs-security.md` for detailed patterns.

| Priority | Check | Method |
|----------|-------|--------|
| Critical | Server Actions auth/authz/validation | Grep |
| Critical | Next.js version CVE assessment | Bash |
| Critical | `NEXT_PUBLIC_` secret exposure | Grep |
| High | Middleware bypass resistance | Grep |
| High | Image optimization SSRF (remotePatterns) | Grep |
| High | CSP & security headers | Grep |
| Medium | Server/Client Component data leakage | Grep |
| Medium | Open redirects | Grep |

## Phase 3: Vercel Infrastructure Audit

See `references/vercel-security.md` for detailed patterns.

| Priority | Check | Method |
|----------|-------|--------|
| Critical | Environment variable secret exposure | CLI (`vercel env ls`) |
| High | Deployment Protection settings | Chrome MCP |
| High | Git Fork Protection | Chrome MCP |
| High | Build Logs/Source Protection | Chrome MCP |
| Medium | Firewall / WAF rules | Chrome MCP |
| Medium | Security headers (vercel.json) | Grep |
| Medium | Deploy Hook exposure | Chrome MCP |

## Phase 4: Supabase Backend Audit

See `references/supabase-security.md` for detailed patterns.

| Priority | Check | Method |
|----------|-------|--------|
| Critical | RLS enabled on all public tables | SQL |
| Critical | service_role key client exposure | Grep |
| Critical | Overly permissive RLS policies | SQL |
| High | SECURITY DEFINER functions | SQL |
| High | SSL enforcement & network restrictions | CLI |
| High | Auth settings (MFA, email confirm, rate limits) | Chrome MCP |
| Medium | Security Advisor findings | Chrome MCP |
| Medium | Storage bucket policies | SQL |
| Medium | anon role function execution privileges | SQL |

## Phase 5: iOS App Audit

See `references/ios-testing.md` for detailed patterns.

| Priority | Check | Method |
|----------|-------|--------|
| Critical | Keychain access attributes | Grep |
| Critical | ATS config & Certificate Pinning | Grep + Bash |
| Critical | Biometric authentication implementation | Grep |
| High | NSUserDefaults sensitive data storage | Grep |
| High | WebView security configuration | Grep |
| Medium | Jailbreak/debugger detection | Grep |
| Medium | Privacy Manifest & ATT | Grep + Bash |

## Phase 6: Cross-Layer Analysis

Evaluate threats that span multiple layers.

- **Auth flow consistency**: Supabase Auth -> JWT -> Vercel Middleware -> iOS Keychain
- **Token lifecycle**: Issuance -> Storage -> Refresh -> Revocation (all stages)
- **API communication security**: Certificate Pinning (iOS) x Vercel Edge x Supabase API
- **Environment variable isolation**: Vercel env (Production/Preview/Development) x Supabase keys
- **Data protection continuity**: Supabase RLS -> API response -> iOS local storage

## Report Format

```markdown
# Full-Stack Security Audit Report
**Target**: [project name]
**Date**: [YYYY-MM-DD]
**Scope**: Next.js / Vercel / Supabase / iOS

## Executive Summary
- Critical: X / High: Y / Medium: Z / Low: W
- Top priority: [one-line summary]

## Layer Summary
| Layer    | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| Next.js  | X | X | X | X |
| Vercel   | X | X | X | X |
| Supabase | X | X | X | X |
| iOS      | X | X | X | X |
| Cross    | X | X | X | X |

## Findings
### [CRITICAL-001] [vulnerability title]
- **Layer**: [Next.js / Vercel / Supabase / iOS / Cross-layer]
- **Category**: OWASP [A01/MASVS-STORAGE/etc.]
- **Location**: `file_path:line_number`
- **Description**: What the vulnerability is
- **Impact**: What happens if exploited
- **Remediation**: diff-format code fix

## Remediation Roadmap
| Priority | Action | Layer |
|----------|--------|-------|
| Immediate | Fix Critical vulnerabilities | - |
| Short-term | Fix High vulnerabilities | - |
| Mid-term | Architecture improvements | - |
```

## Tools & Agents

| Tool | Purpose |
|------|---------|
| **Grep/Glob** | Static pattern detection in code |
| **Bash** | CLI commands (vercel, supabase, npm audit) |
| **Bash (SQL)** | Direct Supabase DB queries (RLS status, etc.) |
| **Chrome MCP** | Vercel/Supabase dashboard settings inspection |
| **security-reviewer** agent | OWASP Top 10 code review |
| **security** role | Threat modeling, CVE correlation |
| **WebSearch** | Latest CVE/advisory lookup |
