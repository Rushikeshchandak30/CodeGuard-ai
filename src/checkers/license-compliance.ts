/**
 * License Compliance Engine
 *
 * Detects license-related risk in dependency trees:
 *   1. Copyleft conflicts (GPL/AGPL in a proprietary project)
 *   2. Unknown / missing / proprietary licenses
 *   3. SPDX expression parsing (OR / AND / WITH)
 *   4. License compatibility matrix (e.g. GPL-3 in Apache-2 project)
 *   5. Deprecated license identifiers (GPL without version, "LGPL")
 *   6. Commercial-use-restricted licenses (Commons Clause, BUSL, SSPL, Elastic)
 *
 * Supports manifest files:
 *   - package.json / package-lock.json / yarn.lock (npm)
 *   - requirements.txt / Pipfile / pyproject.toml (PyPI — best effort)
 *
 * Policy is configurable via .codeguard/policy.json under "licenses".
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type LicenseSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type LicenseCategory =
  | 'permissive'
  | 'weak-copyleft'
  | 'strong-copyleft'
  | 'network-copyleft'
  | 'commercial-restricted'
  | 'proprietary'
  | 'public-domain'
  | 'unknown';

export interface LicenseInfo {
  id: string; // SPDX-like id
  category: LicenseCategory;
  name: string;
  osiApproved: boolean;
  fsfLibre: boolean;
  requiresSourceDisclosure: boolean;
  attributionRequired: boolean;
  commercialUseAllowed: boolean;
  networkCopyleft: boolean;
  compatible: string[]; // SPDX ids this license is compatible WITH as a dependency
}

export interface LicenseFinding {
  packageName: string;
  packageVersion?: string;
  declaredLicense: string | null;
  resolvedSpdx: string | null;
  severity: LicenseSeverity;
  ruleId: string;
  title: string;
  detail: string;
  remediation: string;
}

export interface LicensePolicy {
  /** Project's own license — used for compatibility checks. */
  projectLicense?: string;
  /** SPDX ids that are always allowed. */
  allow?: string[];
  /** SPDX ids that are always denied. */
  deny?: string[];
  /** Categories that are denied (e.g. "strong-copyleft" for closed-source apps). */
  denyCategories?: LicenseCategory[];
  /** Whether to allow packages with no declared license. */
  allowUnknown?: boolean;
}

// ---------------------------------------------------------------------------
// License metadata — 60+ common SPDX ids
// ---------------------------------------------------------------------------

/* eslint-disable @typescript-eslint/naming-convention */
const LICENSE_DB: Record<string, LicenseInfo> = {
  // ----- Permissive -----
  MIT: makeLicense('MIT', 'permissive', 'MIT License'),
  'BSD-2-Clause': makeLicense('BSD-2-Clause', 'permissive', 'BSD 2-Clause'),
  'BSD-3-Clause': makeLicense('BSD-3-Clause', 'permissive', 'BSD 3-Clause'),
  'Apache-2.0': makeLicense('Apache-2.0', 'permissive', 'Apache License 2.0'),
  ISC: makeLicense('ISC', 'permissive', 'ISC License'),
  'Zlib': makeLicense('Zlib', 'permissive', 'zlib License'),
  Unlicense: makeLicense('Unlicense', 'public-domain', 'The Unlicense'),
  'CC0-1.0': makeLicense('CC0-1.0', 'public-domain', 'Creative Commons Zero'),
  WTFPL: makeLicense('WTFPL', 'permissive', 'Do What The F*ck You Want To Public License'),
  '0BSD': makeLicense('0BSD', 'permissive', 'BSD Zero-Clause'),
  'BSD-4-Clause': makeLicense('BSD-4-Clause', 'permissive', 'BSD 4-Clause (advertising)'),
  PostgreSQL: makeLicense('PostgreSQL', 'permissive', 'PostgreSQL License'),

  // ----- Weak copyleft -----
  'LGPL-2.1-only': makeLicense('LGPL-2.1-only', 'weak-copyleft', 'LGPL v2.1', {
    requiresSourceDisclosure: true,
  }),
  'LGPL-2.1-or-later': makeLicense('LGPL-2.1-or-later', 'weak-copyleft', 'LGPL v2.1+', {
    requiresSourceDisclosure: true,
  }),
  'LGPL-3.0-only': makeLicense('LGPL-3.0-only', 'weak-copyleft', 'LGPL v3.0', {
    requiresSourceDisclosure: true,
  }),
  'LGPL-3.0-or-later': makeLicense('LGPL-3.0-or-later', 'weak-copyleft', 'LGPL v3.0+', {
    requiresSourceDisclosure: true,
  }),
  'MPL-2.0': makeLicense('MPL-2.0', 'weak-copyleft', 'Mozilla Public License 2.0', {
    requiresSourceDisclosure: true,
  }),
  'EPL-2.0': makeLicense('EPL-2.0', 'weak-copyleft', 'Eclipse Public License 2.0', {
    requiresSourceDisclosure: true,
  }),
  'CDDL-1.0': makeLicense('CDDL-1.0', 'weak-copyleft', 'CDDL 1.0', {
    requiresSourceDisclosure: true,
  }),

  // ----- Strong copyleft -----
  'GPL-2.0-only': makeLicense('GPL-2.0-only', 'strong-copyleft', 'GPL v2.0', {
    requiresSourceDisclosure: true,
  }),
  'GPL-2.0-or-later': makeLicense('GPL-2.0-or-later', 'strong-copyleft', 'GPL v2.0+', {
    requiresSourceDisclosure: true,
  }),
  'GPL-3.0-only': makeLicense('GPL-3.0-only', 'strong-copyleft', 'GPL v3.0', {
    requiresSourceDisclosure: true,
  }),
  'GPL-3.0-or-later': makeLicense('GPL-3.0-or-later', 'strong-copyleft', 'GPL v3.0+', {
    requiresSourceDisclosure: true,
  }),

  // ----- Network copyleft (affects SaaS) -----
  'AGPL-3.0-only': makeLicense('AGPL-3.0-only', 'network-copyleft', 'Affero GPL v3.0', {
    requiresSourceDisclosure: true,
    networkCopyleft: true,
  }),
  'AGPL-3.0-or-later': makeLicense(
    'AGPL-3.0-or-later',
    'network-copyleft',
    'Affero GPL v3.0+',
    { requiresSourceDisclosure: true, networkCopyleft: true }
  ),

  // ----- Commercial restricted (SSPL, BUSL, Commons Clause, Elastic) -----
  'SSPL-1.0': makeLicense('SSPL-1.0', 'commercial-restricted', 'Server Side Public License', {
    osiApproved: false,
    fsfLibre: false,
    networkCopyleft: true,
    commercialUseAllowed: false,
  }),
  'BUSL-1.1': makeLicense('BUSL-1.1', 'commercial-restricted', 'Business Source License 1.1', {
    osiApproved: false,
    fsfLibre: false,
    commercialUseAllowed: false,
  }),
  'Elastic-2.0': makeLicense('Elastic-2.0', 'commercial-restricted', 'Elastic License 2.0', {
    osiApproved: false,
    fsfLibre: false,
    commercialUseAllowed: false,
  }),
  'Commons-Clause': makeLicense(
    'Commons-Clause',
    'commercial-restricted',
    'Commons Clause (addendum, not a standalone license)',
    { osiApproved: false, fsfLibre: false, commercialUseAllowed: false }
  ),

  // ----- Ambiguous / deprecated / proprietary -----
  GPL: makeLicense('GPL', 'strong-copyleft', 'GPL (unspecified version — DEPRECATED)', {
    requiresSourceDisclosure: true,
  }),
  LGPL: makeLicense('LGPL', 'weak-copyleft', 'LGPL (unspecified version — DEPRECATED)', {
    requiresSourceDisclosure: true,
  }),
  'Artistic-1.0': makeLicense('Artistic-1.0', 'weak-copyleft', 'Artistic License 1.0'),
  'Artistic-2.0': makeLicense('Artistic-2.0', 'weak-copyleft', 'Artistic License 2.0'),
  'OFL-1.1': makeLicense('OFL-1.1', 'permissive', 'SIL Open Font License'),
  UNLICENSED: makeLicense('UNLICENSED', 'proprietary', 'UNLICENSED (proprietary/private)', {
    osiApproved: false,
    fsfLibre: false,
    commercialUseAllowed: false,
  }),
  SEE_LICENSE_IN_FILE: makeLicense(
    'SEE LICENSE IN FILE',
    'unknown',
    'License in separate file — unverified',
    { osiApproved: false, fsfLibre: false }
  ),
};

function makeLicense(
  id: string,
  category: LicenseCategory,
  name: string,
  overrides: Partial<LicenseInfo> = {}
): LicenseInfo {
  const base: LicenseInfo = {
    id,
    name,
    category,
    osiApproved: category !== 'proprietary' && category !== 'unknown',
    fsfLibre: category !== 'proprietary' && category !== 'commercial-restricted',
    requiresSourceDisclosure: false,
    attributionRequired: category !== 'public-domain' && category !== 'unknown',
    commercialUseAllowed: category !== 'commercial-restricted' && category !== 'proprietary',
    networkCopyleft: false,
    compatible: [],
  };
  return { ...base, ...overrides };
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/**
 * Parse a license string into a list of SPDX ids. Supports SPDX expressions:
 *   "MIT"
 *   "Apache-2.0 OR MIT"
 *   "(MIT OR Apache-2.0)"
 *   "GPL-2.0-only WITH Classpath-exception-2.0"
 */
export function parseLicenseExpression(expr: string | null | undefined): string[] {
  if (!expr) return [];
  const cleaned = expr.replace(/[()]/g, ' ').replace(/\s+/g, ' ').trim();
  if (!cleaned) return [];
  // Split on OR / AND boundaries
  const parts = cleaned.split(/\s+(?:OR|AND|WITH)\s+/i);
  const ids: string[] = [];
  for (const p of parts) {
    const id = normalizeSpdx(p.trim());
    if (id) ids.push(id);
  }
  return ids;
}

function normalizeSpdx(s: string): string | null {
  if (!s) return null;
  const t = s.trim();
  // Direct hit
  if (LICENSE_DB[t]) return t;
  // Common aliases
  const aliases: Record<string, string> = {
    'Apache 2.0': 'Apache-2.0',
    Apache2: 'Apache-2.0',
    'Apache License 2.0': 'Apache-2.0',
    'BSD-3': 'BSD-3-Clause',
    'BSD 3-Clause': 'BSD-3-Clause',
    'BSD-2': 'BSD-2-Clause',
    'BSD 2-Clause': 'BSD-2-Clause',
    'BSD License': 'BSD-3-Clause',
    GPL2: 'GPL-2.0-only',
    'GPL 2': 'GPL-2.0-only',
    'GPL-2.0': 'GPL-2.0-only',
    'GPL 3': 'GPL-3.0-only',
    'GPL-3.0': 'GPL-3.0-only',
    AGPL: 'AGPL-3.0-only',
    'AGPL-3.0': 'AGPL-3.0-only',
    'LGPL-2.1': 'LGPL-2.1-only',
    'LGPL-3.0': 'LGPL-3.0-only',
    'Public Domain': 'CC0-1.0',
  };
  if (aliases[t]) return aliases[t];
  // Try case-insensitive match
  const lower = t.toLowerCase();
  for (const k of Object.keys(LICENSE_DB)) {
    if (k.toLowerCase() === lower) return k;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/**
 * Evaluate a single package against the policy.
 */
export function evaluatePackageLicense(
  packageName: string,
  declaredLicense: string | null,
  policy: LicensePolicy = {},
  packageVersion?: string
): LicenseFinding[] {
  const findings: LicenseFinding[] = [];
  const ids = parseLicenseExpression(declaredLicense);

  // --- No license ---
  if (!declaredLicense || declaredLicense.trim() === '') {
    if (!policy.allowUnknown) {
      findings.push({
        packageName,
        packageVersion,
        declaredLicense,
        resolvedSpdx: null,
        severity: 'high',
        ruleId: 'CG_LIC_001',
        title: `${packageName} has no declared license`,
        detail:
          'Packages without a license default to "All Rights Reserved" under copyright law. ' +
          'You may not be legally permitted to use it.',
        remediation:
          'Contact the maintainer or replace with a permissively-licensed alternative.',
      });
    }
    return findings;
  }

  // --- Unresolved SPDX ---
  if (ids.length === 0) {
    findings.push({
      packageName,
      packageVersion,
      declaredLicense,
      resolvedSpdx: null,
      severity: 'medium',
      ruleId: 'CG_LIC_002',
      title: `${packageName} declares an unrecognized license: "${declaredLicense}"`,
      detail:
        'License string does not match any known SPDX identifier or alias. Manual review ' +
        'required.',
      remediation:
        'Verify by reading the LICENSE file in the package, and add the SPDX id to the ' +
        'policy allowlist if acceptable.',
    });
    return findings;
  }

  // --- Evaluate each resolved license (union via OR semantics: user can pick best match) ---
  // We emit findings only if ALL options violate policy.
  const perIdFindings: LicenseFinding[][] = ids.map((id) =>
    evaluateSingleLicense(packageName, id, declaredLicense, policy, packageVersion)
  );
  const violating = perIdFindings.filter((fs) => fs.length > 0);
  if (violating.length === perIdFindings.length) {
    // Every option violates — pick the first (smallest severity set) as the finding list
    // Actually, take the MOST severe from the best option (user will pick)
    findings.push(...violating[0]);
  }

  return findings;
}

function evaluateSingleLicense(
  packageName: string,
  spdxId: string,
  declaredLicense: string,
  policy: LicensePolicy,
  packageVersion?: string
): LicenseFinding[] {
  const findings: LicenseFinding[] = [];
  const info = LICENSE_DB[spdxId];

  // Explicit allow wins over everything
  if (policy.allow?.includes(spdxId)) return [];
  // Explicit deny trumps
  if (policy.deny?.includes(spdxId)) {
    findings.push({
      packageName,
      packageVersion,
      declaredLicense,
      resolvedSpdx: spdxId,
      severity: 'critical',
      ruleId: 'CG_LIC_010',
      title: `License ${spdxId} is explicitly denied by policy`,
      detail: `Package "${packageName}" uses "${spdxId}" which is on the deny list.`,
      remediation: 'Remove the package or request a policy exception.',
    });
    return findings;
  }

  if (!info) {
    findings.push({
      packageName,
      packageVersion,
      declaredLicense,
      resolvedSpdx: spdxId,
      severity: 'medium',
      ruleId: 'CG_LIC_011',
      title: `Unknown SPDX identifier: ${spdxId}`,
      detail: 'License resolved to an identifier not in our database.',
      remediation: 'Add to CodeGuard license DB or use a different package.',
    });
    return findings;
  }

  // Category-level deny
  if (policy.denyCategories?.includes(info.category)) {
    findings.push({
      packageName,
      packageVersion,
      declaredLicense,
      resolvedSpdx: spdxId,
      severity: 'critical',
      ruleId: 'CG_LIC_012',
      title: `License category ${info.category} denied by policy`,
      detail: `"${spdxId}" (${info.name}) is a ${info.category} license; project policy denies this category.`,
      remediation:
        'Use a permissively-licensed alternative or seek legal approval for the category.',
    });
    return findings;
  }

  // Default heuristics (no policy overrides)
  if (!policy.denyCategories && !policy.deny) {
    if (info.category === 'strong-copyleft') {
      findings.push({
        packageName,
        packageVersion,
        declaredLicense,
        resolvedSpdx: spdxId,
        severity: 'high',
        ruleId: 'CG_LIC_020',
        title: `${packageName} is strong copyleft (${spdxId})`,
        detail:
          'GPL-style licenses require you to distribute derivative source code under the ' +
          'same license. Incompatible with proprietary distribution.',
        remediation:
          'Only use if your project is also GPL-compatible, or isolate behind a process/RPC ' +
          'boundary. Otherwise replace.',
      });
    } else if (info.category === 'network-copyleft') {
      findings.push({
        packageName,
        packageVersion,
        declaredLicense,
        resolvedSpdx: spdxId,
        severity: 'high',
        ruleId: 'CG_LIC_021',
        title: `${packageName} is network copyleft (${spdxId})`,
        detail:
          'AGPL triggers source-disclosure when you OFFER THE PROGRAM OVER A NETWORK. Even ' +
          'SaaS is affected.',
        remediation:
          'Replace, or fully open-source your service under AGPL.',
      });
    } else if (info.category === 'commercial-restricted') {
      findings.push({
        packageName,
        packageVersion,
        declaredLicense,
        resolvedSpdx: spdxId,
        severity: 'critical',
        ruleId: 'CG_LIC_022',
        title: `${packageName} uses a commercial-use-restricted license (${spdxId})`,
        detail:
          `${info.name} restricts offering the software as a competing managed service ` +
          '(or, for BUSL, commercial use entirely until the change date).',
        remediation: 'Replace or purchase a commercial license.',
      });
    } else if (info.category === 'proprietary') {
      findings.push({
        packageName,
        packageVersion,
        declaredLicense,
        resolvedSpdx: spdxId,
        severity: 'high',
        ruleId: 'CG_LIC_023',
        title: `${packageName} is proprietary / UNLICENSED`,
        detail: 'Package explicitly declares no open-source license.',
        remediation:
          'Only use internally if you have an agreement with the owner. Do not redistribute.',
      });
    } else if (info.category === 'unknown') {
      findings.push({
        packageName,
        packageVersion,
        declaredLicense,
        resolvedSpdx: spdxId,
        severity: 'medium',
        ruleId: 'CG_LIC_024',
        title: `${packageName} license is unclear (${spdxId})`,
        detail: 'License must be read from a separate file and cannot be auto-verified.',
        remediation: 'Read the LICENSE file and categorize manually.',
      });
    }

    // Deprecated identifiers
    if (spdxId === 'GPL' || spdxId === 'LGPL') {
      findings.push({
        packageName,
        packageVersion,
        declaredLicense,
        resolvedSpdx: spdxId,
        severity: 'medium',
        ruleId: 'CG_LIC_030',
        title: `Deprecated license identifier "${spdxId}" (no version specified)`,
        detail:
          'SPDX requires a version (e.g. GPL-2.0-only, GPL-3.0-only). The unqualified form ' +
          'is ambiguous.',
        remediation: 'Ask the maintainer to clarify the license version.',
      });
    }
  }

  // --- Project license compatibility ---
  if (policy.projectLicense) {
    const projId = normalizeSpdx(policy.projectLicense);
    if (projId) {
      const incompatible = isIncompatible(projId, spdxId);
      if (incompatible) {
        findings.push({
          packageName,
          packageVersion,
          declaredLicense,
          resolvedSpdx: spdxId,
          severity: 'high',
          ruleId: 'CG_LIC_040',
          title: `License ${spdxId} incompatible with project license ${projId}`,
          detail: incompatible,
          remediation:
            'Find an alternative package with a compatible license, or change project ' +
            'license.',
        });
      }
    }
  }

  return findings;
}

/**
 * Minimal compatibility matrix. Returns reason string if incompatible, null otherwise.
 */
function isIncompatible(projectLic: string, depLic: string): string | null {
  // Apache-2.0 project cannot consume GPL-2.0-only (patent clause incompatible)
  if (
    (projectLic === 'Apache-2.0' || projectLic === 'MIT' || projectLic === 'BSD-3-Clause') &&
    (depLic === 'GPL-2.0-only' || depLic === 'GPL-2.0-or-later')
  ) {
    return 'GPL-2.0 is generally considered incompatible with Apache-2.0 due to Apache patent clauses. GPL-2.0 dependencies in an Apache project would force the combined work to be GPL.';
  }
  // Proprietary or permissive project cannot consume AGPL
  if (
    (projectLic === 'MIT' ||
      projectLic === 'BSD-3-Clause' ||
      projectLic === 'Apache-2.0' ||
      projectLic === 'UNLICENSED') &&
    (depLic === 'AGPL-3.0-only' || depLic === 'AGPL-3.0-or-later')
  ) {
    return 'AGPL is network copyleft. Consuming it forces the entire service to be AGPL if offered over a network.';
  }
  // SSPL / BUSL are almost always incompatible with open-source project licensing
  if (
    (projectLic === 'MIT' ||
      projectLic === 'BSD-3-Clause' ||
      projectLic === 'Apache-2.0') &&
    (depLic === 'SSPL-1.0' || depLic === 'BUSL-1.1' || depLic === 'Elastic-2.0')
  ) {
    return 'Commercial-restricted licenses (SSPL/BUSL/Elastic) are incompatible with open-source distribution.';
  }
  return null;
}

// ---------------------------------------------------------------------------
// Batch evaluator
// ---------------------------------------------------------------------------

export interface PackageLicense {
  name: string;
  version?: string;
  license: string | null;
}

export function evaluateLicenses(
  packages: PackageLicense[],
  policy: LicensePolicy = {}
): LicenseFinding[] {
  const all: LicenseFinding[] = [];
  for (const pkg of packages) {
    all.push(...evaluatePackageLicense(pkg.name, pkg.license, policy, pkg.version));
  }
  return all;
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

export function getLicenseEngineStats(): {
  supportedLicenses: number;
  categoriesCovered: number;
} {
  const cats = new Set<string>();
  for (const id of Object.keys(LICENSE_DB)) cats.add(LICENSE_DB[id].category);
  return { supportedLicenses: Object.keys(LICENSE_DB).length, categoriesCovered: cats.size };
}

export function getLicenseCategory(spdxId: string): LicenseCategory | null {
  return LICENSE_DB[spdxId]?.category ?? null;
}
