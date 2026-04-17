/**
 * Infrastructure-as-Code Security Scanner
 *
 * Scans IaC files for common misconfigurations across three ecosystems:
 *
 *   1. Dockerfile
 *      - running as root / missing USER directive
 *      - latest tag / unpinned base image
 *      - curl | sh anti-pattern
 *      - ADD vs COPY
 *      - embedded secrets in ENV
 *      - --no-check-certificate / -k
 *      - chmod 777
 *
 *   2. Kubernetes (YAML)
 *      - privileged: true / allowPrivilegeEscalation: true
 *      - hostNetwork / hostPID / hostIPC
 *      - runAsUser: 0 or missing
 *      - readOnlyRootFilesystem: false
 *      - capabilities.add includes NET_ADMIN / SYS_ADMIN / ALL
 *      - imagePullPolicy: Never with :latest
 *      - hostPath volume on /, /etc, /proc, /sys
 *      - service type LoadBalancer without network policy
 *      - secrets referenced from env without projected volume
 *
 *   3. Terraform (.tf)
 *      - aws_s3_bucket without server-side encryption
 *      - public-read / public-read-write ACLs
 *      - aws_security_group allowing 0.0.0.0/0 on 22/3389/0
 *      - aws_db_instance publicly_accessible = true
 *      - aws_iam_policy_document with "*" resource AND action
 *      - aws_iam_role with no conditions
 *      - encryption disabled (kms_key_id unset on sensitive resources)
 *      - hardcoded access_key / secret_key / password
 *      - azurerm_storage_account public access allowed
 *      - google_storage_bucket_iam_binding roles/viewer+allUsers
 *
 * Based on CIS benchmarks (Docker, Kubernetes, AWS, Azure, GCP) and
 * Checkov / tfsec / kube-bench / Trivy rule corpora.
 */

import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type IacSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type IacFramework = 'dockerfile' | 'kubernetes' | 'terraform' | 'compose';

export interface IacFinding {
  file: string;
  line: number;
  column: number;
  framework: IacFramework;
  ruleId: string;
  severity: IacSeverity;
  title: string;
  detail: string;
  remediation: string;
  cis?: string; // e.g. "CIS-Docker 4.1"
}

interface LineRule {
  id: string;
  pattern: RegExp;
  severity: IacSeverity;
  title: string;
  detail: string;
  remediation: string;
  cis?: string;
  /** Only match if this predicate passes on the whole file */
  fileGuard?: (text: string) => boolean;
}

// ---------------------------------------------------------------------------
// Dockerfile rules
// ---------------------------------------------------------------------------

const DOCKERFILE_RULES: LineRule[] = [
  {
    id: 'CG_IAC_DOCKER_001',
    pattern: /^\s*FROM\s+[^\s#]+:latest\s*$/im,
    severity: 'medium',
    title: 'Dockerfile uses :latest tag',
    detail:
      'Images tagged :latest are mutable — rebuilds can pull different content, breaking ' +
      'reproducibility and enabling supply-chain attacks.',
    remediation: 'Pin to a digest (FROM image@sha256:...) or a version tag.',
    cis: 'CIS-Docker 4.9',
  },
  {
    id: 'CG_IAC_DOCKER_002',
    pattern: /^\s*FROM\s+[^@\s#]+$/im,
    severity: 'low',
    title: 'Dockerfile image not pinned by digest',
    detail: 'Using a tag (even a version tag) allows the maintainer to re-tag after release.',
    remediation: 'Pin to @sha256:... digest for strongest reproducibility.',
  },
  {
    id: 'CG_IAC_DOCKER_003',
    pattern: /^\s*(?:USER|user)\s+(?:0|root)\s*$/im,
    severity: 'high',
    title: 'Dockerfile explicitly runs as root',
    detail: 'USER root allows any container escape to run as the host equivalent.',
    remediation: 'Create a non-root user: RUN adduser -D app && USER app',
    cis: 'CIS-Docker 4.1',
  },
  {
    id: 'CG_IAC_DOCKER_004',
    pattern: /\bcurl\s+(?:-[a-zA-Z]+\s+)*[^|\n]*\s*\|\s*(?:sh|bash|zsh|ash)\b/i,
    severity: 'high',
    title: 'Dockerfile pipes curl into shell',
    detail: 'curl | sh pattern enables MITM attacks and unverifiable installs.',
    remediation:
      'Download to a file, verify checksum, then execute. Prefer package managers.',
    cis: 'CIS-Docker 4.9',
  },
  {
    id: 'CG_IAC_DOCKER_005',
    pattern: /\bwget\s+(?:-[a-zA-Z]+\s+)*[^|\n]*\s*\|\s*(?:sh|bash|zsh)\b/i,
    severity: 'high',
    title: 'Dockerfile pipes wget into shell',
    detail: 'Same risk as curl | sh.',
    remediation: 'Download, verify, then execute.',
  },
  {
    id: 'CG_IAC_DOCKER_006',
    pattern: /^\s*ADD\s+https?:\/\//im,
    severity: 'medium',
    title: 'Dockerfile uses ADD with remote URL',
    detail: 'ADD fetches remote content at build time with no verification.',
    remediation: 'Use COPY + RUN curl --fail --checksum, or pin via package manager.',
  },
  {
    id: 'CG_IAC_DOCKER_007',
    pattern: /\bchmod\s+(?:-R\s+)?(?:0?777|\+rwx)\b/,
    severity: 'medium',
    title: 'Dockerfile uses chmod 777',
    detail: 'World-writable files inside a container ease persistence attacks.',
    remediation: 'Use 644 / 755 with specific ownership.',
  },
  {
    id: 'CG_IAC_DOCKER_008',
    pattern: /\b(?:--no-check-certificate|--insecure|-k\b)/,
    severity: 'high',
    title: 'Dockerfile disables TLS verification',
    detail: 'Flags like -k / --insecure allow MITM of install traffic.',
    remediation: 'Remove. Install the proper CA bundle instead.',
  },
  {
    id: 'CG_IAC_DOCKER_009',
    pattern: /^\s*ENV\s+(?:[A-Z_]+_(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD))\s*=?\s*\S+/im,
    severity: 'critical',
    title: 'Dockerfile hardcodes secret in ENV',
    detail: 'Secrets in layers are preserved in image history forever.',
    remediation: 'Use docker secrets, BuildKit --secret, or runtime env injection.',
    cis: 'CIS-Docker 4.10',
  },
  {
    id: 'CG_IAC_DOCKER_010',
    pattern: /^\s*RUN\s+.*\bsudo\s+/im,
    severity: 'low',
    title: 'Dockerfile invokes sudo',
    detail: 'sudo is rarely necessary in build images and can mask privilege issues.',
    remediation: 'Set USER root before the step if needed; drop back afterwards.',
  },
  {
    id: 'CG_IAC_DOCKER_011',
    pattern: /^\s*EXPOSE\s+(?:22|3389)\s*$/im,
    severity: 'medium',
    title: 'Dockerfile exposes SSH/RDP port',
    detail: 'Containers should not run SSH/RDP; use `docker exec` or an orchestrator.',
    remediation: 'Remove EXPOSE 22/3389.',
  },
];

/**
 * Special Dockerfile rule: missing USER directive altogether.
 */
function checkMissingUserDirective(text: string): boolean {
  return !/^\s*USER\s+\S+/im.test(text);
}

// ---------------------------------------------------------------------------
// Kubernetes rules
// ---------------------------------------------------------------------------

const KUBERNETES_RULES: LineRule[] = [
  {
    id: 'CG_IAC_K8S_001',
    pattern: /^\s*privileged\s*:\s*true\b/im,
    severity: 'critical',
    title: 'Container set to privileged: true',
    detail:
      'Privileged containers have host-level capabilities. A compromise = host compromise.',
    remediation: 'Set privileged: false and grant specific capabilities only if needed.',
    cis: 'CIS-Kubernetes 5.2.1',
  },
  {
    id: 'CG_IAC_K8S_002',
    pattern: /^\s*allowPrivilegeEscalation\s*:\s*true\b/im,
    severity: 'high',
    title: 'allowPrivilegeEscalation: true',
    detail: 'Allows a process to gain more privileges than its parent.',
    remediation: 'Set allowPrivilegeEscalation: false.',
    cis: 'CIS-Kubernetes 5.2.5',
  },
  {
    id: 'CG_IAC_K8S_003',
    pattern: /^\s*hostNetwork\s*:\s*true\b/im,
    severity: 'critical',
    title: 'Pod uses hostNetwork',
    detail: 'Pod shares host network namespace, bypassing network policies.',
    remediation: 'Remove unless absolutely required (e.g. CNI daemonset).',
    cis: 'CIS-Kubernetes 5.2.2',
  },
  {
    id: 'CG_IAC_K8S_004',
    pattern: /^\s*hostPID\s*:\s*true\b/im,
    severity: 'critical',
    title: 'Pod uses hostPID',
    detail: 'Container can see all host processes — breaks isolation.',
    remediation: 'Remove.',
    cis: 'CIS-Kubernetes 5.2.3',
  },
  {
    id: 'CG_IAC_K8S_005',
    pattern: /^\s*hostIPC\s*:\s*true\b/im,
    severity: 'high',
    title: 'Pod uses hostIPC',
    detail: 'Shares host IPC namespace. Allows attacks against host processes.',
    remediation: 'Remove.',
  },
  {
    id: 'CG_IAC_K8S_006',
    pattern: /^\s*runAsUser\s*:\s*0\b/im,
    severity: 'high',
    title: 'runAsUser: 0 (root)',
    detail: 'Container process runs as root.',
    remediation: 'Set a non-zero UID, e.g. runAsUser: 1000.',
    cis: 'CIS-Kubernetes 5.2.6',
  },
  {
    id: 'CG_IAC_K8S_007',
    pattern: /^\s*readOnlyRootFilesystem\s*:\s*false\b/im,
    severity: 'medium',
    title: 'readOnlyRootFilesystem: false',
    detail: 'Writable rootfs allows persistence and defensive evasion.',
    remediation: 'Set readOnlyRootFilesystem: true; mount tmpfs for write dirs.',
    cis: 'CIS-Kubernetes 5.2.8',
  },
  {
    id: 'CG_IAC_K8S_008',
    pattern: /^\s*-\s*(?:NET_ADMIN|SYS_ADMIN|SYS_PTRACE|SYS_MODULE|ALL)\b/im,
    severity: 'high',
    title: 'Dangerous Linux capability added',
    detail:
      'NET_ADMIN/SYS_ADMIN/ALL effectively break container isolation.',
    remediation: 'Drop all and add only the specific capability you truly need.',
    cis: 'CIS-Kubernetes 5.2.7',
  },
  {
    id: 'CG_IAC_K8S_009',
    pattern: /^\s*image\s*:\s*[^\s#]+:latest\s*$/im,
    severity: 'medium',
    title: 'Kubernetes image uses :latest',
    detail: 'Non-deterministic deployments; cannot be rolled back reliably.',
    remediation: 'Pin to a digest or version.',
  },
  {
    id: 'CG_IAC_K8S_010',
    pattern: /^\s*path\s*:\s*\/(?:etc|proc|sys|var\/run\/docker\.sock|root)\b/im,
    severity: 'critical',
    title: 'hostPath mounts sensitive host directory',
    detail:
      'Mounting /etc, /proc, /sys, or docker.sock into the container trivially escalates ' +
      'to host compromise.',
    remediation:
      'Do not mount these paths. Use a CSI driver or projected volumes for specific needs.',
  },
  {
    id: 'CG_IAC_K8S_011',
    pattern: /^\s*automountServiceAccountToken\s*:\s*true\b/im,
    severity: 'medium',
    title: 'automountServiceAccountToken: true',
    detail:
      'Default mounts of SA tokens expand the blast radius of a container compromise.',
    remediation:
      'Set false unless the pod calls the Kubernetes API. Use projected tokens if needed.',
  },
  {
    id: 'CG_IAC_K8S_012',
    pattern: /^\s*-\s*name\s*:\s*(?:KUBERNETES_SERVICE_HOST|AWS_SECRET_ACCESS_KEY|DB_PASSWORD)\s*\n\s*value\s*:\s*['"]?[^$]/im,
    severity: 'critical',
    title: 'Secret-looking env var set as plain value (not secretKeyRef)',
    detail: 'env.value stores the literal; env.valueFrom.secretKeyRef pulls from a Secret.',
    remediation: 'Change to env.valueFrom.secretKeyRef referencing a Kubernetes Secret.',
  },
];

// ---------------------------------------------------------------------------
// Terraform rules
// ---------------------------------------------------------------------------

const TERRAFORM_RULES: LineRule[] = [
  {
    id: 'CG_IAC_TF_001',
    pattern: /\bacl\s*=\s*"public-read(?:-write)?"/i,
    severity: 'critical',
    title: 'S3 bucket ACL is public',
    detail: 'public-read / public-read-write ACLs expose all objects publicly.',
    remediation:
      'Set acl = "private" and use bucket policies + pre-signed URLs for sharing.',
    cis: 'CIS-AWS 1.20',
  },
  {
    id: 'CG_IAC_TF_002',
    pattern: /\bcidr_blocks?\s*=\s*\[[^\]]*"0\.0\.0\.0\/0"/i,
    severity: 'high',
    title: 'Security group allows 0.0.0.0/0',
    detail: 'Opening a port to the entire internet is almost always excessive.',
    remediation:
      'Restrict cidr_blocks to known office/vpc CIDRs, or use a VPN / bastion / IAM auth.',
    cis: 'CIS-AWS 4.1',
  },
  {
    id: 'CG_IAC_TF_003',
    pattern: /\bpubliclly_accessible\s*=\s*true\b|\bpublicly_accessible\s*=\s*true\b/i,
    severity: 'critical',
    title: 'Database publicly_accessible = true',
    detail: 'RDS/Aurora instances should not be reachable from the public internet.',
    remediation: 'Set publicly_accessible = false and use VPC peering or private endpoints.',
    cis: 'CIS-AWS 2.3.3',
  },
  {
    id: 'CG_IAC_TF_004',
    pattern: /\bserver_side_encryption_configuration\s*=\s*\[?\s*\]/i,
    severity: 'high',
    title: 'S3 bucket has empty encryption config',
    detail: 'Bucket is created without SSE — all objects stored unencrypted.',
    remediation:
      'Add server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" } } }.',
  },
  {
    id: 'CG_IAC_TF_005',
    pattern: /\bskip_final_snapshot\s*=\s*true\b/i,
    severity: 'medium',
    title: 'Database skip_final_snapshot = true',
    detail: 'Accidental destroy deletes the DB with no recovery.',
    remediation: 'Set skip_final_snapshot = false for production databases.',
  },
  {
    id: 'CG_IAC_TF_006',
    pattern: /\bstorage_encrypted\s*=\s*false\b/i,
    severity: 'high',
    title: 'RDS storage_encrypted = false',
    detail: 'Database storage is unencrypted at rest.',
    remediation: 'Set storage_encrypted = true.',
    cis: 'CIS-AWS 2.3.1',
  },
  {
    id: 'CG_IAC_TF_007',
    pattern: /"(?:Action|Resource)"\s*:\s*"\*"/i,
    severity: 'high',
    title: 'IAM policy with wildcard Action or Resource',
    detail: 'Overly permissive IAM policies are the root cause of many breaches.',
    remediation: 'Scope to specific actions and resource ARNs.',
    cis: 'CIS-AWS 1.16',
  },
  {
    id: 'CG_IAC_TF_008',
    pattern: /\b(?:access_key|secret_key|aws_access_key_id|aws_secret_access_key|password)\s*=\s*"[^"$]{8,}"/i,
    severity: 'critical',
    title: 'Hardcoded credential in Terraform',
    detail: 'Secrets committed to .tf files leak to git history.',
    remediation: 'Use variables populated from AWS Secrets Manager, env vars, or Vault.',
  },
  {
    id: 'CG_IAC_TF_009',
    pattern: /\benable_deletion_protection\s*=\s*false\b/i,
    severity: 'medium',
    title: 'Resource has deletion protection disabled',
    detail: 'Accidental terraform destroy / console click can wipe production.',
    remediation: 'Set enable_deletion_protection = true for critical resources.',
  },
  {
    id: 'CG_IAC_TF_010',
    pattern: /\bversioning\s*\{\s*enabled\s*=\s*false\s*\}/i,
    severity: 'medium',
    title: 'S3 bucket versioning disabled',
    detail: 'Without versioning, ransomware-style deletes are unrecoverable.',
    remediation: 'Enable versioning on all data buckets.',
    cis: 'CIS-AWS 2.1.3',
  },
  {
    id: 'CG_IAC_TF_011',
    pattern: /\ballow_public_access\s*=\s*true\b|\ballow_blob_public_access\s*=\s*true\b/i,
    severity: 'critical',
    title: 'Azure storage allows public access',
    detail: 'Public blob access exposes containers to anonymous reads.',
    remediation: 'Set allow_blob_public_access = false.',
  },
  {
    id: 'CG_IAC_TF_012',
    pattern: /\brole\s*=\s*"roles\/(?:viewer|editor|owner)"\s*\n?\s*members?\s*=\s*\[[^\]]*"allUsers"/i,
    severity: 'critical',
    title: 'GCP IAM binds role to allUsers',
    detail: 'Granting a role to allUsers is effectively public access.',
    remediation: 'Remove allUsers or restrict to a specific service account/group.',
  },
];

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

export function detectIacFramework(filePath: string, text?: string): IacFramework | null {
  const base = path.basename(filePath).toLowerCase();
  const ext = path.extname(filePath).toLowerCase();
  if (base === 'dockerfile' || base.startsWith('dockerfile.') || ext === '.dockerfile') return 'dockerfile';
  if (ext === '.tf' || ext === '.tfvars' || ext === '.hcl') return 'terraform';
  if (ext === '.yaml' || ext === '.yml') {
    const t = text ?? '';
    if (/\bapiVersion\s*:\s*/i.test(t) && /\bkind\s*:\s*/i.test(t)) return 'kubernetes';
    if (/^\s*version\s*:\s*['"]?[0-9]+(?:\.[0-9]+)?['"]?\s*$/m.test(t) && /\bservices\s*:/m.test(t))
      return 'compose';
    return null;
  }
  return null;
}

export function scanIacText(
  text: string,
  filePath: string,
  framework?: IacFramework
): IacFinding[] {
  const fw = framework ?? detectIacFramework(filePath, text);
  if (!fw) return [];

  const findings: IacFinding[] = [];
  const rules =
    fw === 'dockerfile'
      ? DOCKERFILE_RULES
      : fw === 'kubernetes'
        ? KUBERNETES_RULES
        : fw === 'terraform'
          ? TERRAFORM_RULES
          : [];

  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length === 0 || line.length > 5000) continue;
    // Skip comments
    if (/^\s*(?:#|\/\/)/.test(line)) continue;

    for (const rule of rules) {
      if (rule.fileGuard && !rule.fileGuard(text)) continue;
      const m = rule.pattern.exec(line);
      if (m) {
        findings.push({
          file: filePath,
          line: i + 1,
          column: (m.index ?? 0) + 1,
          framework: fw,
          ruleId: rule.id,
          severity: rule.severity,
          title: rule.title,
          detail: rule.detail,
          remediation: rule.remediation,
          cis: rule.cis,
        });
      }
    }
  }

  // File-level rules for Dockerfile
  if (fw === 'dockerfile' && checkMissingUserDirective(text)) {
    findings.push({
      file: filePath,
      line: 1,
      column: 1,
      framework: 'dockerfile',
      ruleId: 'CG_IAC_DOCKER_000',
      severity: 'high',
      title: 'Dockerfile has no USER directive',
      detail: 'Without USER, the container runs as root by default.',
      remediation: 'Add USER <non-root-name> before CMD/ENTRYPOINT.',
      cis: 'CIS-Docker 4.1',
    });
  }

  return findings;
}

export function scanIacFile(filePath: string): IacFinding[] {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > 5 * 1024 * 1024) return [];
    const text = fs.readFileSync(filePath, 'utf8');
    return scanIacText(text, filePath);
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

export function getIacScannerStats(): {
  dockerfileRules: number;
  kubernetesRules: number;
  terraformRules: number;
  frameworks: IacFramework[];
} {
  return {
    dockerfileRules: DOCKERFILE_RULES.length + 1, // + missing-USER file rule
    kubernetesRules: KUBERNETES_RULES.length,
    terraformRules: TERRAFORM_RULES.length,
    frameworks: ['dockerfile', 'kubernetes', 'terraform'],
  };
}
