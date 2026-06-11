export interface AuditChecklistItem {
  id: string;
  category: "dns" | "http" | "email" | "access" | "firebase";
  title: string;
  description: string;
  isCompleted: boolean;
  severity: "high" | "medium" | "low";
}

export interface SecurityScanStep {
  name: string;
  status: "idle" | "running" | "success" | "warning" | "failed";
  progress: number;
  resultMessage?: string;
}

export interface DomainReport {
  domain: string;
  timestamp: string;
  score: number;
  steps: SecurityScanStep[];
}
