import type { Finding, ScanResult } from '../types/findings.js';

export interface SecurityMetrics {
  totalIssues: number;
  highSeverity: number;
  mediumSeverity: number;
  lowSeverity: number;
  securityScore: number;
  vulnerabilityDensity: number;
  trend: 'improving' | 'declining' | 'stable';
}

export interface TrendData {
  timestamp: Date;
  metrics: SecurityMetrics;
}

/**
 * Calculate security score (0-100, higher is better)
 */
export function calculateSecurityScore(findings: Finding[]): number {
  const high = findings.filter(f => f.severity === 'HIGH').length;
  const medium = findings.filter(f => f.severity === 'MEDIUM').length;
  const low = findings.filter(f => f.severity === 'LOW').length;
  
  // Weighted scoring: High issues have more impact
  const totalWeight = (high * 10) + (medium * 5) + (low * 2);
  
  // Maximum reasonable weight for scoring (adjust based on project size)
  const maxWeight = 100;
  
  // Calculate score (100 is perfect, 0 is worst)
  const score = Math.max(0, Math.min(100, 100 - (totalWeight / maxWeight) * 100));
  
  return Math.round(score);
}

/**
 * Calculate vulnerability density (issues per 1000 lines of code)
 */
export function calculateVulnerabilityDensity(
  findings: Finding[],
  scannedFiles: number
): number {
  if (scannedFiles === 0) return 0;
  
  // Estimate: average 200 lines per file
  const estimatedLines = scannedFiles * 200;
  const density = (findings.length / estimatedLines) * 1000;
  
  return Math.round(density * 10) / 10;
}

/**
 * Generate security metrics from scan result
 */
export function generateMetrics(result: ScanResult): SecurityMetrics {
  const { findings, scannedFiles } = result;
  
  const high = findings.filter(f => f.severity === 'HIGH').length;
  const medium = findings.filter(f => f.severity === 'MEDIUM').length;
  const low = findings.filter(f => f.severity === 'LOW').length;
  
  return {
    totalIssues: findings.length,
    highSeverity: high,
    mediumSeverity: medium,
    lowSeverity: low,
    securityScore: calculateSecurityScore(findings),
    vulnerabilityDensity: calculateVulnerabilityDensity(findings, scannedFiles),
    trend: 'stable', // Will be calculated when comparing with previous metrics
  };
}

/**
 * Compare metrics to determine trend
 */
export function compareTrends(
  current: SecurityMetrics,
  previous: SecurityMetrics
): 'improving' | 'declining' | 'stable' {
  const scoreDiff = current.securityScore - previous.securityScore;
  const issueDiff = current.totalIssues - previous.totalIssues;
  
  // Improving if score increased or issues decreased
  if (scoreDiff > 5 || issueDiff < -2) {
    return 'improving';
  }
  
  // Declining if score decreased or issues increased
  if (scoreDiff < -5 || issueDiff > 2) {
    return 'declining';
  }
  
  return 'stable';
}

/**
 * Generate ASCII chart for trend visualization
 */
export function generateTrendChart(metrics: SecurityMetrics[]): string {
  if (metrics.length < 2) {
    return 'Insufficient data for trend chart (need at least 2 scans)';
  }
  
  const maxScore = 100;
  const chartHeight = 10;
  const chartWidth = Math.min(metrics.length, 20);
  
  let chart = '\n```\nSecurity Score Trend (Last ' + chartWidth + ' Scans)\n\n';
  
  // Take last N metrics
  const recentMetrics = metrics.slice(-chartWidth);
  
  // Generate chart rows (top to bottom)
  for (let row = chartHeight; row >= 0; row--) {
    const threshold = (row / chartHeight) * maxScore;
    chart += threshold.toFixed(0).padStart(3) + ' │';
    
    for (const metric of recentMetrics) {
      const score = metric.securityScore;
      if (score >= threshold - 5) {
        chart += '█';
      } else {
        chart += ' ';
      }
    }
    chart += '\n';
  }
  
  // Add x-axis
  chart += '    └' + '─'.repeat(chartWidth) + '\n';
  chart += '     ' + 'Scan History →'.padEnd(chartWidth) + '\n';
  chart += '```\n';
  
  return chart;
}

/**
 * Generate metrics dashboard markdown
 */
export function generateMetricsDashboard(
  current: SecurityMetrics,
  previous?: SecurityMetrics
): string {
  let dashboard = '\n### 📊 Security Metrics Dashboard\n\n';
  
  // Security Score
  const scoreEmoji = current.securityScore >= 80 ? '🟢' : 
                     current.securityScore >= 60 ? '🟡' : '🔴';
  dashboard += `**Security Score:** ${scoreEmoji} ${current.securityScore}/100`;
  
  if (previous) {
    const diff = current.securityScore - previous.securityScore;
    const trendEmoji = diff > 0 ? '📈' : diff < 0 ? '📉' : '➡️';
    dashboard += ` ${trendEmoji} ${diff > 0 ? '+' : ''}${diff}`;
  }
  dashboard += '\n\n';
  
  // Vulnerability Density
  dashboard += `**Vulnerability Density:** ${current.vulnerabilityDensity} issues per 1K lines\n\n`;
  
  // Issue Breakdown
  dashboard += '**Issue Breakdown:**\n';
  dashboard += `- 🔴 High: ${current.highSeverity}`;
  if (previous) {
    const diff = current.highSeverity - previous.highSeverity;
    if (diff !== 0) dashboard += ` (${diff > 0 ? '+' : ''}${diff})`;
  }
  dashboard += '\n';
  
  dashboard += `- 🟡 Medium: ${current.mediumSeverity}`;
  if (previous) {
    const diff = current.mediumSeverity - previous.mediumSeverity;
    if (diff !== 0) dashboard += ` (${diff > 0 ? '+' : ''}${diff})`;
  }
  dashboard += '\n';
  
  dashboard += `- 🔵 Low: ${current.lowSeverity}`;
  if (previous) {
    const diff = current.lowSeverity - previous.lowSeverity;
    if (diff !== 0) dashboard += ` (${diff > 0 ? '+' : ''}${diff})`;
  }
  dashboard += '\n\n';
  
  // Trend Analysis
  if (previous) {
    const trend = compareTrends(current, previous);
    const trendText = trend === 'improving' ? '✅ **Improving** - Security posture is getting better' :
                      trend === 'declining' ? '⚠️ **Declining** - Security posture needs attention' :
                      'ℹ️ **Stable** - Security posture is consistent';
    dashboard += `**Trend:** ${trendText}\n\n`;
  }
  
  return dashboard;
}
