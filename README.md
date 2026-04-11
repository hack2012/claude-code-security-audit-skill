# Claude Code Security Audit Skill

A comprehensive, full-stack security audit skill for [Claude Code](https://claude.ai/code). Run `/security-audit all` and get an end-to-end vulnerability assessment across your entire stack.

## Supported Stack (v1)

| Layer | Technology | Standard |
|-------|-----------|----------|
| **Application** | Next.js (App Router, Server Actions, Middleware) | OWASP Top 10:2025, WSTG |
| **Infrastructure** | Vercel (env vars, WAF, deployment protection) | Vercel Security Best Practices |
| **Backend** | Supabase (RLS, Auth, Storage, Edge Functions) | Supabase Hardening Guide |
| **Mobile** | iOS (Swift, UIKit/SwiftUI) | OWASP MASVS v2 / MASTG |
| **General Web** | Any web framework | OWASP WSTG |

## Quick Start

### Option 1: Git Submodule (recommended)

```bash
cd ~/.claude
git submodule add git@github.com:toshipon/claude-code-security-audit-skill.git skills/security-audit
```

### Option 2: Manual Copy

```bash
git clone git@github.com:toshipon/claude-code-security-audit-skill.git
cp -r claude-code-security-audit-skill/ ~/.claude/skills/security-audit/
```

### Usage

```
/security-audit              # Interactive target selection
/security-audit all          # Full-stack audit (recommended)
/security-audit nextjs       # Next.js only
/security-audit vercel       # Vercel only
/security-audit supabase     # Supabase only
/security-audit ios          # iOS only
/security-audit web          # Next.js + Vercel + Supabase
```

## Architecture

```
security-audit/
├── SKILL.md                          # Main skill (loaded into context)
├── README.md                         # This file
└── references/                       # Detailed guides (loaded on demand)
    ├── nextjs-security.md            # Next.js: Server Actions, Middleware, CSP, CVEs
    ├── vercel-security.md            # Vercel: CLI checks + Chrome MCP dashboard
    ├── supabase-security.md          # Supabase: RLS SQL queries + Chrome MCP dashboard
    ├── ios-testing.md                # iOS: MASVS v2 all 8 categories
    └── web-testing.md                # General web: OWASP WSTG + Top 10:2025
```

### Design Principles

- **Progressive Disclosure** — SKILL.md stays under 160 lines. Detailed grep patterns and SQL queries live in `references/`, loaded only when needed. ([Anthropic best practice](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices))
- **Evidence-First** — Every finding includes file path, line number, and a concrete remediation. Inspired by [Trail of Bits skills](https://github.com/trailofbits/skills).
- **CLI + Chrome MCP** — Automate what CLI/API can reach; use Chrome DevTools MCP for dashboard-only settings (Vercel Security, Supabase Auth config).

## Audit Phases

| Phase | Target | Method |
|-------|--------|--------|
| 1. Reconnaissance | Project structure | Glob, Read |
| 2. Next.js Audit | Server Actions, Middleware, CSP, env vars | Grep, Bash |
| 3. Vercel Audit | Env vars, WAF, deployment protection | CLI, Chrome MCP |
| 4. Supabase Audit | RLS, auth config, SECURITY DEFINER funcs | SQL, CLI, Chrome MCP |
| 5. iOS Audit | Keychain, ATS, biometrics, WebView | Grep, Bash |
| 6. Cross-Layer | Auth flow, token lifecycle, data protection | Analysis |

## Roadmap

### v1.0 (Current)
- [x] Next.js (App Router, Server Actions, Middleware, CSP)
- [x] Vercel (env vars, WAF, deployment protection, security headers)
- [x] Supabase (RLS, Auth, Storage, Edge Functions, Splinter lint)
- [x] iOS (MASVS v2 / MASTG all 8 categories)
- [x] General Web (OWASP WSTG + Top 10:2025)
- [x] Chrome MCP dashboard inspection

### v1.1 — Mobile Expansion
- [ ] Android (MASVS v2 / MASTG — Kotlin/Java)
- [ ] Flutter (Dart security patterns, platform channel security)
- [ ] Swift (macOS/watchOS/tvOS beyond iOS)
- [ ] React Native security patterns

### v1.2 — Backend Expansion
- [ ] Python (Django, FastAPI, Flask — OWASP + Bandit patterns)
- [ ] Go (common vulnerability patterns, goroutine safety)
- [ ] Ruby on Rails (Brakeman patterns)
- [ ] Rust (unsafe blocks, memory safety audit)

### v1.3 — Infrastructure as Code
- [ ] Terraform (AWS/GCP/Azure misconfigurations)
- [ ] AWS Well-Architected Framework (Security Pillar)
  - IAM least privilege
  - Encryption at rest/in transit
  - Network segmentation (VPC, Security Groups)
  - Logging & monitoring (CloudTrail, GuardDuty)
- [ ] GCP Security Best Practices
- [ ] Azure Security Benchmark

### v1.4 — Compliance & Regulatory
- [ ] Financial-grade security (PCI-DSS, SOX compliance)
- [ ] HIPAA (healthcare data protection)
- [ ] GDPR / CCPA (privacy compliance)
- [ ] SOC 2 Type II controls mapping
- [ ] ISO 27001 controls verification

### v1.5 — Advanced Detection
- [ ] Supply chain security (SBOM, dependency provenance)
- [ ] Container security (Dockerfile, Kubernetes RBAC)
- [ ] CI/CD pipeline security (GitHub Actions, Vercel builds)
- [ ] Secret scanning (git history, build artifacts)
- [ ] LLM/AI security (OWASP Top 10 for LLM)

## References

- [OWASP Top 10:2025](https://owasp.org/Top10/)
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP MASVS v2](https://mas.owasp.org/MASVS/)
- [OWASP MASTG](https://mas.owasp.org/MASTG/)
- [Trail of Bits Security Skills](https://github.com/trailofbits/skills)
- [Anthropic Skill Best Practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)

## Contributing

PRs welcome! When adding a new reference:

1. Create `references/<technology>-security.md`
2. Follow the existing format: detection patterns (grep/bash), Chrome MCP steps, common misconfigs table, checklist
3. Add the technology to the relevant phase in `SKILL.md`
4. Update this README's roadmap

## License

MIT
