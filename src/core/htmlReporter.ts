import { writeFile } from "fs/promises";
import { resolve } from "path";
import type { Finding, Severity, ScanResult } from "../types/findings.js";

export class HtmlReporter {
  async generateReport(result: ScanResult, outputPath: string): Promise<void> {
    const html = this.buildHtml(result);
    await writeFile(resolve(outputPath), html, "utf-8");
  }

  private groupFindings(findings: Finding[]): Map<string, Finding[]> {
    const grouped = new Map<string, Finding[]>();
    
    for (const finding of findings) {
      const key = `${finding.ruleId}::${finding.description}`;
      if (!grouped.has(key)) {
        grouped.set(key, []);
      }
      grouped.get(key)!.push(finding);
    }
    
    return grouped;
  }

  private buildHtml(result: ScanResult): string {
    const { findings } = result;
    const high = findings.filter((f) => f.severity === "HIGH");
    const medium = findings.filter((f) => f.severity === "MEDIUM");
    const low = findings.filter((f) => f.severity === "LOW");

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>React Native Security Report - ${result.timestamp.toLocaleDateString()}</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Segoe UI', 'Roboto', sans-serif;
      background: #0a0e1a;
      min-height: 100vh;
      color: #e4e6eb;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }
    
    .container {
      max-width: 1400px;
      margin: 0 auto;
      padding: 40px 20px 80px;
    }

    .scan-status {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 12px;
      padding: 16px 24px;
      margin-bottom: 24px;
      background: rgba(34, 197, 94, 0.1);
      border: 1px solid rgba(34, 197, 94, 0.3);
      border-radius: 12px;
      color: #22c55e;
      font-size: 15px;
      font-weight: 500;
    }

    .scan-status svg {
      width: 20px;
      height: 20px;
      flex-shrink: 0;
    }

    .scan-status-text {
      color: #e4e6eb;
    }

    .scan-status .divider {
      color: #6b7280;
      margin: 0 4px;
    }
    
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 32px;
      padding: 32px;
      background: #141824;
      border: 1px solid #1f2937;
      border-radius: 16px;
    }
    
    .header-left {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .header-icon {
      width: 48px;
      height: 48px;
      background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      box-shadow: 0 4px 12px rgba(34, 197, 94, 0.2);
    }

    .header-icon svg {
      width: 28px;
      height: 28px;
      color: #ffffff;
    }
    
    .header h1 {
      font-size: 32px;
      font-weight: 600;
      color: #ffffff;
      letter-spacing: -0.5px;
    }

    .header-subtitle {
      font-size: 14px;
      color: #9ca3af;
      margin-top: 4px;
      font-weight: 400;
    }

    .header-info {
      display: flex;
      align-items: center;
      gap: 12px;
      color: #9ca3af;
      font-size: 14px;
    }

    .info-divider {
      opacity: 0.5;
    }
    
    .summary {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1px;
      background: #1a1f2e;
      border: 1px solid #1a1f2e;
      border-radius: 12px;
      overflow: hidden;
      margin-bottom: 32px;
    }
    
    .summary-card {
      background: #141824;
      padding: 48px 32px;
      text-align: center;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      border-right: 1px solid #1a1f2e;
      cursor: pointer;
      position: relative;
      overflow: hidden;
    }

    .summary-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 4px;
      background: transparent;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .summary-card:last-child {
      border-right: none;
    }
    
    .summary-card:hover {
      background: #1a1f2e;
      transform: translateY(-2px);
    }

    .summary-card.active {
      background: linear-gradient(180deg, rgba(34, 197, 94, 0.08) 0%, #141824 100%);
      border-color: rgba(34, 197, 94, 0.2);
    }

    .summary-card.active::before {
      background: linear-gradient(90deg, #22c55e 0%, #4ade80 50%, #22c55e 100%);
      background-size: 200% 100%;
      animation: shimmer 3s ease-in-out infinite;
    }

    @keyframes shimmer {
      0%, 100% {
        background-position: 0% 0%;
      }
      50% {
        background-position: 100% 0%;
      }
    }

    .summary-card.active .number {
      text-shadow: 0 0 20px rgba(74, 222, 128, 0.3);
    }
    
    .summary-card .number {
      font-size: 64px;
      font-weight: 700;
      line-height: 1;
      letter-spacing: -2px;
      margin-bottom: 12px;
    }
    
    .summary-card.high .number { color: #ef4444; }
    .summary-card.medium .number { color: #f97316; }
    .summary-card.low .number { color: #eab308; }
    .summary-card.total .number { color: #60a5fa; }
    
    .summary-card h3 {
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #9ca3af;
      font-weight: 500;
    }
    
    .findings {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    
    .finding-group {
      background: #141824;
      border: 1px solid #1f2937;
      border-radius: 12px;
      overflow: hidden;
      transition: all 0.2s ease;
      margin-bottom: 12px;
    }
    
    .finding-group:hover {
      border-color: #374151;
      background: #1a1f2e;
    }

    .finding {
      background: #0d1117;
      border: 1px solid #1f2937;
      border-radius: 8px;
      overflow: hidden;
      transition: all 0.2s ease;
      cursor: pointer;
      margin-bottom: 8px;
    }

    .finding:last-child {
      margin-bottom: 0;
    }
    
    .finding:hover {
      border-color: #374151;
      background: #161b22;
    }
    
    .group-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 24px 28px;
      gap: 20px;
      cursor: pointer;
    }

    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 20px 24px;
      gap: 20px;
      cursor: pointer;
    }
    
    .finding-left {
      display: flex;
      align-items: center;
      gap: 16px;
      flex: 1;
      min-width: 0;
    }
    
    .severity-badge {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      white-space: nowrap;
      flex-shrink: 0;
    }

    .severity-icon {
      width: 18px;
      height: 18px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .severity-icon svg {
      width: 12px;
      height: 12px;
    }
    
    .severity-badge.high {
      background: rgba(239, 68, 68, 0.15);
      color: #ef4444;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }

    .severity-badge.high .severity-icon {
      background: #ef4444;
      color: #ffffff;
    }
    
    .severity-badge.medium {
      background: rgba(249, 115, 22, 0.15);
      color: #f97316;
      border: 1px solid rgba(249, 115, 22, 0.3);
    }

    .severity-badge.medium .severity-icon {
      background: #f97316;
      color: #ffffff;
    }
    
    .severity-badge.low {
      background: rgba(234, 179, 8, 0.15);
      color: #eab308;
      border: 1px solid rgba(234, 179, 8, 0.3);
    }

    .severity-badge.low .severity-icon {
      background: #eab308;
      color: #ffffff;
    }
    
    .finding-title {
      font-size: 16px;
      font-weight: 500;
      color: #f3f4f6;
      letter-spacing: -0.2px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .occurrence-count {
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      background: rgba(96, 165, 250, 0.15);
      border: 1px solid rgba(96, 165, 250, 0.3);
      border-radius: 12px;
      font-size: 12px;
      font-weight: 600;
      color: #60a5fa;
      margin-left: 12px;
      white-space: nowrap;
    }

    .debug-badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 4px 10px;
      background: rgba(168, 85, 247, 0.15);
      border: 1px solid rgba(168, 85, 247, 0.3);
      border-radius: 12px;
      font-size: 11px;
      font-weight: 600;
      color: #a855f7;
      margin-left: 8px;
      white-space: nowrap;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .debug-badge svg {
      width: 12px;
      height: 12px;
      flex-shrink: 0;
    }

    .instances-container {
      max-height: 0;
      overflow: hidden;
      transition: max-height 0.3s ease;
      border-top: 1px solid transparent;
    }

    .finding-group.expanded .instances-container {
      max-height: 5000px;
      border-top-color: #1f2937;
    }

    .instances-list {
      padding: 20px 24px;
    }
    
    .expand-icon {
      color: #6b7280;
      transition: transform 0.3s ease;
      flex-shrink: 0;
      width: 20px;
      height: 20px;
    }
    
    .finding-group.expanded > .group-header .expand-icon,
    .finding.expanded .expand-icon {
      transform: rotate(90deg);
    }
    
    .finding-content {
      max-height: 0;
      overflow: hidden;
      transition: max-height 0.3s ease;
      border-top: 1px solid transparent;
    }
    
    .finding.expanded .finding-content {
      max-height: 2000px;
      border-top-color: #1f2937;
    }
    
    .finding-content-inner {
      padding: 24px 28px;
    }
    
    .finding-description {
      color: #9ca3af;
      font-size: 15px;
      line-height: 1.6;
      margin-bottom: 20px;
    }
    
    .finding-location {
      display: flex;
      align-items: center;
      gap: 10px;
      color: #6b7280;
      font-size: 13px;
      margin-bottom: 20px;
      font-family: 'SF Mono', 'Monaco', 'Menlo', monospace;
    }
    
    .finding-location svg {
      width: 16px;
      height: 16px;
      flex-shrink: 0;
    }

    .line-number-badge {
      display: inline-flex;
      align-items: center;
      padding: 2px 8px;
      background: rgba(59, 130, 246, 0.15);
      color: #60a5fa;
      border: 1px solid rgba(59, 130, 246, 0.3);
      border-radius: 4px;
      font-size: 12px;
      font-weight: 600;
      font-family: 'SF Mono', 'Monaco', 'Menlo', monospace;
      margin-left: 8px;
      white-space: nowrap;
    }

    .file-path {
      color: #9ca3af;
      word-break: break-all;
    }
    
    .code-snippet {
      background: #0d1117;
      border: 1px solid #1f2937;
      border-radius: 8px;
      margin-bottom: 20px;
      overflow-x: auto;
    }
    
    .code-snippet pre {
      font-family: 'SF Mono', 'Menlo', 'Monaco', 'Courier New', monospace;
      font-size: 12px;
      line-height: 1.7;
      color: #e4e6eb;
      margin: 0;
      padding: 0;
    }

    .code-line {
      display: flex;
      padding: 3px 16px;
      min-height: 22px;
    }

    .code-line:hover {
      background: rgba(255, 255, 255, 0.03);
    }

    .code-line.highlighted {
      background: rgba(239, 68, 68, 0.15);
      border-left: 3px solid #ef4444;
      padding-left: 17px;
    }

    .code-line.highlighted.medium {
      background: rgba(249, 115, 22, 0.15);
      border-left-color: #f97316;
    }

    .code-line.highlighted.low {
      background: rgba(234, 179, 8, 0.15);
      border-left-color: #eab308;
    }

    .line-number {
      flex-shrink: 0;
      width: 40px;
      text-align: right;
      color: #6b7280;
      user-select: none;
      padding-right: 12px;
      font-weight: 500;
      font-size: 11px;
    }

    .code-line.highlighted .line-number {
      color: #ef4444;
      font-weight: 700;
    }

    .code-line.highlighted.medium .line-number {
      color: #f97316;
    }

    .code-line.highlighted.low .line-number {
      color: #eab308;
    }

    .line-content {
      flex: 1;
      white-space: pre;
      overflow-x: auto;
    }
    
    .reason-box {
      background: rgba(239, 68, 68, 0.08);
      border: 1px solid rgba(239, 68, 68, 0.2);
      border-left: 3px solid #ef4444;
      padding: 16px 20px;
      border-radius: 8px;
      margin-bottom: 16px;
    }
    
    .reason-title {
      font-weight: 600;
      color: #ef4444;
      margin-bottom: 8px;
      font-size: 13px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .reason-text {
      color: #e4e6eb;
      line-height: 1.6;
      font-size: 14px;
    }
    
    .suggestion {
      background: rgba(34, 197, 94, 0.08);
      border: 1px solid rgba(34, 197, 94, 0.2);
      border-left: 3px solid #22c55e;
      padding: 16px 20px;
      border-radius: 8px;
    }
    
    .suggestion-title {
      font-weight: 600;
      color: #22c55e;
      margin-bottom: 8px;
      font-size: 13px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .suggestion-text {
      color: #9ca3af;
      line-height: 1.6;
      font-size: 14px;
    }
    
    .no-findings {
      text-align: center;
      padding: 120px 40px;
      background: #141824;
      border-radius: 12px;
      border: 1px solid #1f2937;
    }
    
    .no-findings svg {
      width: 64px;
      height: 64px;
      margin-bottom: 20px;
      color: #22c55e;
    }
    
    .no-findings h2 {
      font-size: 28px;
      margin-bottom: 12px;
      font-weight: 600;
      color: #f3f4f6;
    }
    
    .no-findings p {
      font-size: 16px;
      color: #9ca3af;
    }

    .footer {
      text-align: center;
      margin-top: 64px;
      padding: 32px 24px;
      border-top: 1px solid #1f2937;
      color: #6b7280;
      font-size: 13px;
    }

    .footer-content {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      margin-bottom: 12px;
    }

    .footer-logo {
      font-size: 18px;
      font-weight: 700;
      color: #f3f4f6;
      letter-spacing: -0.5px;
    }

    .footer-version {
      display: inline-block;
      padding: 2px 8px;
      background: rgba(59, 130, 246, 0.1);
      border: 1px solid rgba(59, 130, 246, 0.3);
      border-radius: 6px;
      font-size: 11px;
      color: #60a5fa;
      font-weight: 600;
      margin-left: 8px;
    }
    
    @media (max-width: 1024px) {
      .summary {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    @media (max-width: 768px) {
      .header {
        flex-direction: column;
        align-items: flex-start;
        gap: 12px;
      }

      .summary {
        grid-template-columns: 1fr;
      }

      .summary-card {
        border-right: none;
        border-bottom: 1px solid #1a1f2e;
        padding: 36px 24px;
      }

      .summary-card:last-child {
        border-bottom: none;
      }

      .summary-card .number {
        font-size: 48px;
      }
      
      .finding-header {
        padding: 20px;
      }

      .finding-content-inner {
        padding: 20px;
      }
      
      .finding-title {
        font-size: 14px;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="scan-status">
      <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
      </svg>
      <span>Scan completed in <span class="scan-status-text">${(result.duration / 1000).toFixed(1)}s</span> <span class="divider">•</span> <span class="scan-status-text">${result.scannedFiles || 0} files analyzed</span></span>
    </div>

    <div class="header">
      <div class="header-left">
        <div class="header-icon">
          <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
          </svg>
        </div>
        <div>
          <h1>Static Analysis Report</h1>
          <div class="header-subtitle">RNSEC - React Native & Expo Security Scanner</div>
        </div>
      </div>
      <div class="header-info">
        <div class="info-item">${result.timestamp.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })} • ${result.timestamp.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true })}</div>
      </div>
    </div>
    
    <div class="summary">
      <div class="summary-card total active" onclick="filterBySeverity('all')" data-filter="all">
        <div class="number">${findings.length}</div>
        <h3>Total</h3>
      </div>
      <div class="summary-card high" onclick="filterBySeverity('high')" data-filter="high">
        <div class="number">${high.length}</div>
        <h3>High</h3>
      </div>
      <div class="summary-card medium" onclick="filterBySeverity('medium')" data-filter="medium">
        <div class="number">${medium.length}</div>
        <h3>Medium</h3>
      </div>
      <div class="summary-card low" onclick="filterBySeverity('low')" data-filter="low">
        <div class="number">${low.length}</div>
        <h3>Low</h3>
      </div>
    </div>
    
    ${
      findings.length > 0
        ? `
    <div class="findings">
      ${this.renderFindings(high, "HIGH")}
      ${this.renderFindings(medium, "MEDIUM")}
      ${this.renderFindings(low, "LOW")}
    </div>
    `
        : `
    <div class="no-findings">
      <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
      </svg>
      <h2>No Security Issues Found!</h2>
      <p>Your React Native app passed all security checks.</p>
    </div>
    `
    }

    <div class="footer">
      <div class="footer-content">
        <span class="footer-logo">rnsec</span>
        <span class="footer-version">v1.0.0</span>
      </div>
      <p>React Native & Expo Security Scanner</p>
      <p style="margin-top: 8px; opacity: 0.6; font-size: 12px;">
        Professional-grade static analysis for mobile security
      </p>
    </div>
  </div>
  
  <script>
    let currentFilter = 'all';

    function toggleGroup(element) {
      element.classList.toggle('expanded');
    }

    function toggleFinding(element) {
      element.classList.toggle('expanded');
    }

    function filterBySeverity(severity) {
      currentFilter = severity;
      const groups = document.querySelectorAll('.finding-group');
      const cards = document.querySelectorAll('.summary-card');
      
      // Update active state on cards
      cards.forEach(card => {
        if (card.dataset.filter === severity) {
          card.classList.add('active');
        } else {
          card.classList.remove('active');
        }
      });
      
      // Filter finding groups
      groups.forEach(group => {
        if (severity === 'all') {
          group.style.display = 'block';
        } else if (group.classList.contains(severity)) {
          group.style.display = 'block';
        } else {
          group.style.display = 'none';
        }
      });
    }

    // Add click handlers to group headers
    document.querySelectorAll('.group-header').forEach(header => {
      header.addEventListener('click', function(e) {
        e.stopPropagation();
        toggleGroup(this.parentElement);
      });
    });

    // Add click handlers to individual findings
    document.querySelectorAll('.finding').forEach(finding => {
      finding.addEventListener('click', function(e) {
        // Don't toggle if clicking on code snippet or links
        if (e.target.closest('.code-snippet') || e.target.tagName === 'A') {
          return;
        }
        e.stopPropagation();
        toggleFinding(this);
      });
    });
  </script>
</body>
</html>`;
  }

  private renderFindings(findings: Finding[], severityLabel: string): string {
    const grouped = this.groupFindings(findings);
    const result: string[] = [];

    for (const [key, groupedFindings] of grouped) {
      const firstFinding = groupedFindings[0];
      const count = groupedFindings.length;
      const severityClass = severityLabel.toLowerCase();

      // If only one occurrence, render it directly without grouping
      if (count === 1) {
        result.push(this.renderSingleFinding(firstFinding, severityLabel));
        continue;
      }

      // Multiple occurrences - render as a group
      // Check if all instances are in debug context
      const allInDebug = groupedFindings.every(f => f.isDebugContext);
      const someInDebug = groupedFindings.some(f => f.isDebugContext);
      
      result.push(`
      <div class="finding-group ${severityClass}" data-severity="${severityClass}">
        <div class="group-header">
          <div class="finding-left">
            <span class="severity-badge ${severityClass}">
              <span class="severity-icon">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
              </span>
              ${severityLabel}
            </span>
            <div class="finding-title">
              ${this.escapeHtml(firstFinding.description || firstFinding.ruleId)}
              <span class="occurrence-count">${count} occurrence${count > 1 ? 's' : ''}</span>
              ${allInDebug ? `
                <span class="debug-badge">
                  <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path>
                  </svg>
                  Debug Only
                </span>
              ` : someInDebug ? `
                <span class="debug-badge">
                  <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path>
                  </svg>
                  Some in Debug
                </span>
              ` : ''}
            </div>
          </div>
          <svg class="expand-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
          </svg>
        </div>
        
        <div class="instances-container">
          <div class="instances-list">
            ${groupedFindings.map(finding => this.renderFindingInstance(finding, severityLabel)).join('')}
          </div>
        </div>
      </div>
      `);
    }

    return result.join('');
  }

  private renderSingleFinding(finding: Finding, severityLabel: string): string {
    const severityClass = severityLabel.toLowerCase();
    return `
      <div class="finding-group ${severityClass}" data-severity="${severityClass}">
        ${this.renderFindingInstance(finding, severityLabel, true)}
      </div>
    `;
  }

  private renderFindingInstance(finding: Finding, severityLabel: string, isStandalone: boolean = false): string {
    const severityClass = severityLabel.toLowerCase();
    
    if (isStandalone) {
      // For standalone findings, use the group header style
      return `
        <div class="group-header">
          <div class="finding-left">
            <span class="severity-badge ${severityClass}">
              <span class="severity-icon">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
              </span>
              ${severityLabel}
            </span>
            <div class="finding-title">
              ${this.escapeHtml(finding.description || finding.ruleId)}
              ${finding.isDebugContext ? `
                <span class="debug-badge">
                  <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path>
                  </svg>
                  Debug Only
                </span>
              ` : ''}
            </div>
          </div>
          <svg class="expand-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
          </svg>
        </div>
        
        <div class="instances-container">
          <div class="instances-list">
            ${this.renderFindingContent(finding, severityLabel, true)}
          </div>
        </div>
      `;
    }
    
    return `
      <div class="finding">
        <div class="finding-header">
          <div class="finding-left">
            <div class="finding-location" style="margin: 0; display: flex; align-items: center; gap: 8px;">
              <div style="display: flex; align-items: center; gap: 8px; flex: 1; flex-wrap: wrap;">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                </svg>
                <span class="file-path">${this.escapeHtml(finding.filePath)}</span>
                ${finding.line ? `<span class="line-number-badge">Line ${finding.line}</span>` : ''}
              </div>
              ${finding.isDebugContext ? `
                <span class="debug-badge" style="margin: 0;">
                  <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path>
                  </svg>
                  Debug
                </span>
              ` : ''}
            </div>
          </div>
          <svg class="expand-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
          </svg>
        </div>
        
        <div class="finding-content">
          ${this.renderFindingContent(finding, severityLabel, false)}
        </div>
      </div>
    `;
  }

  private renderFindingContent(finding: Finding, severityLabel: string, isStandalone: boolean): string {
    return `
      <div class="finding-content-inner">
        ${!isStandalone && finding.description ? `
          <div class="finding-description">${this.escapeHtml(finding.description)}</div>
        ` : ''}
            
        ${isStandalone ? `
            <div class="finding-location">
              <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
              </svg>
            <span class="file-path">${this.escapeHtml(finding.filePath)}</span>
            ${finding.line ? `<span class="line-number-badge">Line ${finding.line}</span>` : ''}
            </div>
        ` : ''}
            
        ${finding.snippet ? `
            <div class="code-snippet">
            ${this.formatCodeSnippet(finding.snippet, finding.line, severityLabel)}
          </div>
        ` : ''}
        
        ${finding.reason ? `
          <div class="reason-box">
            <div class="reason-title">
              ⚠️ Why this matters
            </div>
            <div class="reason-text">${this.escapeHtml(finding.reason)}</div>
          </div>
        ` : ''}
            
        ${finding.suggestion ? `
            <div class="suggestion">
              <div class="suggestion-title">
                💡 Recommendation
              </div>
            <div class="suggestion-text">${this.escapeHtml(finding.suggestion)}</div>
          </div>
        ` : ''}
      </div>
    `;
  }

  private formatCodeSnippet(snippet: string, targetLine: number | undefined, severity: string): string {
    const lines = snippet.split('\n');
    const startLine = targetLine ? Math.max(1, targetLine - 2) : 1;
    
    return lines.map((line, index) => {
      const lineNumber = startLine + index;
      const isHighlighted = lineNumber === targetLine;
      const severityClass = severity.toLowerCase();
      
      return `<div class="code-line ${isHighlighted ? `highlighted ${severityClass}` : ''}">
  <span class="line-number">${lineNumber}</span>
  <span class="line-content">${this.escapeHtml(line)}</span>
</div>`;
    }).join('');
  }

  private escapeHtml(text: string): string {
    const map: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;",
    };
    return text.replace(/[&<>"']/g, (m) => map[m]);
  }
}
