// =============================================================================
// DevSecOps Arsenal — a curated catalogue of the best DevSecOps tools.
//
// Curated from the community "awesome-devsecops" lists (the devsecops org,
// tysoncung, sottlmarek). These are external, open-source server / CLI / CI
// tools — they run on your machine or pipeline, NOT inside the browser. DevSec
// Toolbox simply helps you discover and compare them. Star counts are rounded
// approximations and drift over time.
//
// Loaded lazily (only when the Arsenal view is opened) to keep the toolbox light.
// =============================================================================

export const ARSENAL_CATS = [
  'SAST',          // static application security testing
  'DAST',          // dynamic / runtime scanning
  'SCA',           // software composition / dependency analysis
  'Secrets',       // secret & credential detection
  'Containers',    // image & container security
  'IaC',           // infrastructure-as-code scanning
  'Cloud',         // cloud posture (CSPM)
  'Supply Chain',  // SBOM, signing, provenance, policy
  'Learn',         // reference & learning resources
];

// cat = one of ARSENAL_CATS · stars = rounded GitHub stars (approx) · repo = owner/name
export const ARSENAL = [
  // ---------------- SAST ----------------
  { name: 'Semgrep', cat: 'SAST', stars: 11000, repo: 'semgrep/semgrep', url: 'https://github.com/semgrep/semgrep',
    desc: 'Fast, open static analysis across 30+ languages with human-readable custom rules — a modern SAST staple.' , tags: ['multi-lang', 'rules', 'ci'] },
  { name: 'CodeQL', cat: 'SAST', stars: 8000, repo: 'github/codeql', url: 'https://github.com/github/codeql',
    desc: 'Semantic code-analysis engine that treats code as data you can query; powers GitHub code scanning.', tags: ['semantic', 'github'] },
  { name: 'SonarQube', cat: 'SAST', stars: 9500, repo: 'SonarSource/sonarqube', url: 'https://github.com/SonarSource/sonarqube',
    desc: 'Continuous inspection of code quality and security with quality gates for your pipeline.', tags: ['quality', 'self-host'] },
  { name: 'Bandit', cat: 'SAST', stars: 7000, repo: 'PyCQA/bandit', url: 'https://github.com/PyCQA/bandit',
    desc: 'Finds common security issues in Python code — the go-to Python SAST linter.', tags: ['python'] },
  { name: 'gosec', cat: 'SAST', stars: 8500, repo: 'securego/gosec', url: 'https://github.com/securego/gosec',
    desc: 'Inspects Go source for security problems by scanning the AST.', tags: ['go'] },
  { name: 'Brakeman', cat: 'SAST', stars: 7200, repo: 'presidentbeef/brakeman', url: 'https://github.com/presidentbeef/brakeman',
    desc: 'Static analysis security scanner purpose-built for Ruby on Rails apps.', tags: ['ruby', 'rails'] },

  // ---------------- DAST ----------------
  { name: 'OWASP ZAP', cat: 'DAST', stars: 13000, repo: 'zaproxy/zaproxy', url: 'https://github.com/zaproxy/zaproxy',
    desc: 'The flagship open web-app scanner / intercepting proxy for finding runtime vulnerabilities.', tags: ['owasp', 'proxy', 'web'] },
  { name: 'Nuclei', cat: 'DAST', stars: 21000, repo: 'projectdiscovery/nuclei', url: 'https://github.com/projectdiscovery/nuclei',
    desc: 'Blazing-fast, template-driven vulnerability scanner with a huge community template library.', tags: ['templates', 'fast'] },
  { name: 'Nikto', cat: 'DAST', stars: 8500, repo: 'sullo/nikto', url: 'https://github.com/sullo/nikto',
    desc: 'Classic web-server scanner that checks for thousands of dangerous files and misconfigurations.', tags: ['web-server'] },
  { name: 'Wapiti', cat: 'DAST', stars: 1300, repo: 'wapiti-scanner/wapiti', url: 'https://github.com/wapiti-scanner/wapiti',
    desc: 'Black-box web application vulnerability scanner (SQLi, XSS, SSRF, and more).', tags: ['black-box', 'web'] },

  // ---------------- SCA ----------------
  { name: 'Trivy', cat: 'SCA', stars: 24000, repo: 'aquasecurity/trivy', url: 'https://github.com/aquasecurity/trivy',
    desc: 'All-in-one scanner for dependencies, containers, IaC, and secrets — fast and CI-friendly.', tags: ['all-in-one', 'ci', 'containers'] },
  { name: 'OWASP Dependency-Check', cat: 'SCA', stars: 6500, repo: 'jeremylong/DependencyCheck', url: 'https://github.com/jeremylong/DependencyCheck',
    desc: 'Detects publicly disclosed vulnerabilities in your project dependencies (CVE/NVD).', tags: ['owasp', 'cve'] },
  { name: 'Grype', cat: 'SCA', stars: 9500, repo: 'anchore/grype', url: 'https://github.com/anchore/grype',
    desc: 'Vulnerability scanner for container images and filesystems, pairs with Syft SBOMs.', tags: ['sbom', 'images'] },
  { name: 'OSV-Scanner', cat: 'SCA', stars: 6700, repo: 'google/osv-scanner', url: 'https://github.com/google/osv-scanner',
    desc: "Google's scanner that matches your lockfiles against the open OSV vulnerability database.", tags: ['osv', 'lockfile'] },
  { name: 'Renovate', cat: 'SCA', stars: 17000, repo: 'renovatebot/renovate', url: 'https://github.com/renovatebot/renovate',
    desc: 'Automated dependency updates with granular rules — keep libraries patched continuously.', tags: ['updates', 'automation'] },

  // ---------------- Secrets ----------------
  { name: 'Gitleaks', cat: 'Secrets', stars: 18000, repo: 'gitleaks/gitleaks', url: 'https://github.com/gitleaks/gitleaks',
    desc: 'Scans git repos and history for hardcoded secrets, keys, and tokens.', tags: ['git', 'pre-commit'] },
  { name: 'TruffleHog', cat: 'Secrets', stars: 18000, repo: 'trufflesecurity/trufflehog', url: 'https://github.com/trufflesecurity/trufflehog',
    desc: 'Finds and verifies leaked credentials across repos, CI, and 800+ secret types.', tags: ['verify', 'repos'] },
  { name: 'detect-secrets', cat: 'Secrets', stars: 4000, repo: 'Yelp/detect-secrets', url: 'https://github.com/Yelp/detect-secrets',
    desc: "Yelp's pre-commit secret scanner built around an auditable baseline.", tags: ['pre-commit', 'baseline'] },
  { name: 'git-secrets', cat: 'Secrets', stars: 12000, repo: 'awslabs/git-secrets', url: 'https://github.com/awslabs/git-secrets',
    desc: 'Prevents you from committing AWS keys and other secrets via git hooks.', tags: ['aws', 'hooks'] },

  // ---------------- Containers ----------------
  { name: 'Hadolint', cat: 'Containers', stars: 10000, repo: 'hadolint/hadolint', url: 'https://github.com/hadolint/hadolint',
    desc: 'Dockerfile linter that enforces best practices and catches insecure instructions.', tags: ['dockerfile', 'lint'] },
  { name: 'Falco', cat: 'Containers', stars: 7500, repo: 'falcosecurity/falco', url: 'https://github.com/falcosecurity/falco',
    desc: 'CNCF runtime security — detects anomalous behaviour in containers and Kubernetes via syscalls.', tags: ['runtime', 'k8s', 'cncf'] },
  { name: 'Clair', cat: 'Containers', stars: 10000, repo: 'quay/clair', url: 'https://github.com/quay/clair',
    desc: 'Static analysis of vulnerabilities in application container image layers.', tags: ['images', 'layers'] },
  { name: 'Dockle', cat: 'Containers', stars: 2800, repo: 'goodwithtech/dockle', url: 'https://github.com/goodwithtech/dockle',
    desc: 'Container image linter for security and Dockerfile best-practice / CIS checks.', tags: ['lint', 'cis'] },
  { name: 'Docker Bench Security', cat: 'Containers', stars: 9500, repo: 'docker/docker-bench-security', url: 'https://github.com/docker/docker-bench-security',
    desc: 'Script that checks dozens of CIS Docker Benchmark best practices on a host.', tags: ['cis', 'host'] },

  // ---------------- IaC ----------------
  { name: 'Checkov', cat: 'IaC', stars: 7200, repo: 'bridgecrewio/checkov', url: 'https://github.com/bridgecrewio/checkov',
    desc: 'Policy-as-code scanner for Terraform, CloudFormation, Kubernetes, Helm, ARM, and more.', tags: ['terraform', 'policy', 'k8s'] },
  { name: 'tfsec', cat: 'IaC', stars: 6700, repo: 'aquasecurity/tfsec', url: 'https://github.com/aquasecurity/tfsec',
    desc: 'Fast static analysis for Terraform; now part of the Trivy family.', tags: ['terraform'] },
  { name: 'Terrascan', cat: 'IaC', stars: 4700, repo: 'tenable/terrascan', url: 'https://github.com/tenable/terrascan',
    desc: 'Detects compliance and security violations across IaC using 500+ policies.', tags: ['compliance', 'opa'] },
  { name: 'KICS', cat: 'IaC', stars: 2300, repo: 'Checkmarx/kics', url: 'https://github.com/Checkmarx/kics',
    desc: 'Finds security vulnerabilities and misconfigurations in IaC at build time.', tags: ['misconfig'] },
  { name: 'kube-bench', cat: 'IaC', stars: 7200, repo: 'aquasecurity/kube-bench', url: 'https://github.com/aquasecurity/kube-bench',
    desc: 'Checks whether Kubernetes is deployed per the CIS Kubernetes Benchmark.', tags: ['k8s', 'cis'] },

  // ---------------- Cloud ----------------
  { name: 'Prowler', cat: 'Cloud', stars: 11000, repo: 'prowler-cloud/prowler', url: 'https://github.com/prowler-cloud/prowler',
    desc: 'Open cloud security tool for AWS, Azure, GCP, and Kubernetes — hundreds of checks.', tags: ['aws', 'azure', 'gcp'] },
  { name: 'ScoutSuite', cat: 'Cloud', stars: 7000, repo: 'nccgroup/ScoutSuite', url: 'https://github.com/nccgroup/ScoutSuite',
    desc: 'Multi-cloud security auditing that produces a clear posture report.', tags: ['audit', 'multi-cloud'] },
  { name: 'Steampipe', cat: 'Cloud', stars: 7200, repo: 'turbot/steampipe', url: 'https://github.com/turbot/steampipe',
    desc: 'Query your cloud, SaaS, and infra with SQL — great for posture and compliance checks.', tags: ['sql', 'posture'] },
  { name: 'CloudSploit', cat: 'Cloud', stars: 3000, repo: 'aquasecurity/cloudsploit', url: 'https://github.com/aquasecurity/cloudsploit',
    desc: 'Detects security risks in cloud accounts across AWS, Azure, GCP, and Oracle.', tags: ['cspm'] },

  // ---------------- Supply Chain ----------------
  { name: 'Syft', cat: 'Supply Chain', stars: 6700, repo: 'anchore/syft', url: 'https://github.com/anchore/syft',
    desc: 'Generates a Software Bill of Materials (SBOM) from images and filesystems.', tags: ['sbom'] },
  { name: 'Cosign', cat: 'Supply Chain', stars: 4700, repo: 'sigstore/cosign', url: 'https://github.com/sigstore/cosign',
    desc: 'Container signing, verification, and storage from the Sigstore project.', tags: ['signing', 'sigstore'] },
  { name: 'Open Policy Agent', cat: 'Supply Chain', stars: 10000, repo: 'open-policy-agent/opa', url: 'https://github.com/open-policy-agent/opa',
    desc: 'General-purpose policy engine (Rego) for authz, admission control, and policy-as-code.', tags: ['policy', 'rego', 'cncf'] },
  { name: 'in-toto', cat: 'Supply Chain', stars: 2900, repo: 'in-toto/in-toto', url: 'https://github.com/in-toto/in-toto',
    desc: 'Framework that cryptographically secures the integrity of software supply chains.', tags: ['provenance'] },

  // ---------------- Learn ----------------
  { name: 'awesome-devsecops', cat: 'Learn', stars: 5500, repo: 'devsecops/awesome-devsecops', url: 'https://github.com/devsecops/awesome-devsecops',
    desc: 'The community-curated master list of DevSecOps tools and resources this Arsenal draws from.', tags: ['list', 'reference'] },
  { name: 'DevSecOps Bootcamp', cat: 'Learn', stars: 6500, repo: 'devsecops/bootcamp', url: 'https://github.com/devsecops/bootcamp',
    desc: 'Hands-on learning material to level up on DevSecOps practices.', tags: ['course', 'hands-on'] },
  { name: 'OWASP Top 10', cat: 'Learn', stars: 0, repo: 'OWASP/Top10', url: 'https://owasp.org/www-project-top-ten/',
    desc: 'The standard awareness document for the most critical web application security risks.', tags: ['owasp', 'standard'] },
  { name: 'OWASP Cheat Sheet Series', cat: 'Learn', stars: 29000, repo: 'OWASP/CheatSheetSeries', url: 'https://github.com/OWASP/CheatSheetSeries',
    desc: 'Concise, high-value security guidance on specific application-security topics.', tags: ['owasp', 'guides'] },
];
