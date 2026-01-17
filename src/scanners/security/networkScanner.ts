import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;
import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { Severity, type Finding } from '../../types/findings.js';
import { getLineNumber, extractSnippet } from '../../utils/stringUtils.js';
import { RuleCategory } from '../../types/ruleTypes.js';

const insecureHttpUrlRule: Rule = {
  id: 'INSECURE_HTTP_URL',
  description: 'Insecure HTTP URLs detected in network requests',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        if (node.callee.type === 'Identifier' && node.callee.name === 'fetch') {
          const urlArg = node.arguments[0];
          
          if (urlArg && urlArg.type === 'StringLiteral') {
            const url = urlArg.value;
            
            if (url.startsWith('http://')) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'INSECURE_HTTP_URL',
                description: `Insecure HTTP URL detected in fetch: "${url}"`,
                severity: Severity.MEDIUM,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Use HTTPS instead of HTTP for all network requests',
              });
            }
          }
        }
        
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'axios'
        ) {
          const urlArg = node.arguments[0];
          
          if (urlArg && urlArg.type === 'StringLiteral') {
            const url = urlArg.value;
            
            if (url.startsWith('http://')) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              
              findings.push({
                ruleId: 'INSECURE_HTTP_URL',
                description: `Insecure HTTP URL detected in axios: "${url}"`,
                severity: Severity.MEDIUM,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Use HTTPS instead of HTTP for all network requests',
              });
            }
          }
        }
      },
      
      ObjectProperty(path: any) {
        const { node } = path;
        
        if (
          (node.key.type === 'Identifier' && node.key.name === 'baseURL') &&
          node.value.type === 'StringLiteral'
        ) {
          const url = node.value.value;
          
          if (url.startsWith('http://')) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'INSECURE_HTTP_URL',
              description: `Insecure HTTP baseURL detected: "${url}"`,
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Use HTTPS instead of HTTP for all network requests',
            });
          }
        }
      },
    });

    return findings;
  },
};

const insecureWebViewRule: Rule = {
  id: 'INSECURE_WEBVIEW',
  description: 'WebView with insecure configuration detected',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    traverse(context.ast, {
      JSXElement(path: any) {
        const { node } = path;
        
        if (
          node.openingElement.name.type === 'JSXIdentifier' &&
          node.openingElement.name.name === 'WebView'
        ) {
          let hasJavaScriptEnabled = false;
          let hasWildcardOrigin = false;
          
          node.openingElement.attributes.forEach((attr: any) => {
            if (attr.type === 'JSXAttribute' && attr.name.type === 'JSXIdentifier') {
              if (attr.name.name === 'javaScriptEnabled') {
                if (
                  attr.value &&
                  attr.value.type === 'JSXExpressionContainer' &&
                  attr.value.expression.type === 'BooleanLiteral' &&
                  attr.value.expression.value === true
                ) {
                  hasJavaScriptEnabled = true;
                }
              }
              
              if (attr.name.name === 'originWhitelist') {
                if (
                  attr.value &&
                  attr.value.type === 'JSXExpressionContainer' &&
                  attr.value.expression.type === 'ArrayExpression'
                ) {
                  attr.value.expression.elements.forEach((el: any) => {
                    if (el && el.type === 'StringLiteral' && el.value === '*') {
                      hasWildcardOrigin = true;
                    }
                  });
                }
              }
            }
          });
          
          if (hasJavaScriptEnabled && hasWildcardOrigin) {
            const line = getLineNumber(context.fileContent, node.start || 0);
            
            findings.push({
              ruleId: 'INSECURE_WEBVIEW',
              description: 'WebView with javaScriptEnabled and wildcard originWhitelist',
              severity: Severity.HIGH,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Restrict originWhitelist to specific domains and disable JavaScript if not needed',
            });
          }
        }
      },
    });

    return findings;
  },
};

const noRequestTimeoutRule: Rule = {
  id: 'NO_REQUEST_TIMEOUT',
  description: 'Network request without timeout configuration',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    if (!context.ast) {
      return findings;
    }

    traverse(context.ast, {
      CallExpression(path: any) {
        const { node } = path;
        
        // Check for fetch without timeout
        if (node.callee.type === 'Identifier' && node.callee.name === 'fetch') {
          const optionsArg = node.arguments[1];
          
          if (!optionsArg || optionsArg.type !== 'ObjectExpression') {
            const line = getLineNumber(context.fileContent, node.start || 0);
            findings.push({
              ruleId: 'NO_REQUEST_TIMEOUT',
              description: 'fetch() without timeout - vulnerable to slowloris DoS',
              severity: Severity.MEDIUM,
              filePath: context.filePath,
              line,
              snippet: extractSnippet(context.fileContent, line),
              suggestion: 'Add timeout to fetch using AbortSignal with setTimeout, or use a library like axios with timeout config.',
            });
          } else {
            // Check if timeout/signal is present
            const hasTimeout = optionsArg.properties.some((prop: any) => 
              prop.key && (prop.key.name === 'signal' || prop.key.name === 'timeout')
            );
            
            if (!hasTimeout) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              findings.push({
                ruleId: 'NO_REQUEST_TIMEOUT',
                description: 'fetch() without timeout configuration',
                severity: Severity.MEDIUM,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Add timeout using AbortSignal: const controller = new AbortController(); setTimeout(() => controller.abort(), 30000);',
              });
            }
          }
        }
        
        // Check for axios without timeout
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.name === 'axios'
        ) {
          const configArg = node.arguments[1] || node.arguments[0];
          
          if (configArg && configArg.type === 'ObjectExpression') {
            const hasTimeout = configArg.properties.some((prop: any) => 
              prop.key && prop.key.name === 'timeout'
            );
            
            if (!hasTimeout) {
              const line = getLineNumber(context.fileContent, node.start || 0);
              findings.push({
                ruleId: 'NO_REQUEST_TIMEOUT',
                description: 'axios request without timeout configuration',
                severity: Severity.MEDIUM,
                filePath: context.filePath,
                line,
                snippet: extractSnippet(context.fileContent, line),
                suggestion: 'Add timeout to axios config: { timeout: 30000 } to prevent hanging requests.',
              });
            }
          }
        }
      },
    });

    return findings;
  },
};

const weakTlsConfigurationRule: Rule = {
  id: 'WEAK_TLS_CONFIGURATION',
  description: 'Weak TLS configuration detected',
  severity: Severity.MEDIUM,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const findings: Finding[] = [];
    
    const content = context.fileContent;

    // Check for TLS 1.0/1.1 usage
    if (content.includes('TLSv1.0') || content.includes('TLSv1.1') || content.includes('TLSv1_0') || content.includes('TLSv1_1')) {
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('TLSv1.0') || lines[i].includes('TLSv1.1') || lines[i].includes('TLSv1_0') || lines[i].includes('TLSv1_1')) {
          findings.push({
            ruleId: 'WEAK_TLS_CONFIGURATION',
            description: 'Weak TLS version (< 1.2) configured - deprecated and insecure',
            severity: Severity.HIGH,
            filePath: context.filePath,
            line: i + 1,
            snippet: lines[i].trim(),
            suggestion: 'Use TLS 1.2 or higher. TLS 1.0 and 1.1 are deprecated and have known vulnerabilities.',
          });
        }
      }
    }

    // Check for insecure httpsAgent configuration
    if (content.includes('httpsAgent') && (content.includes('rejectUnauthorized') || content.includes('secureProtocol'))) {
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('rejectUnauthorized') && lines[i].includes('false')) {
          findings.push({
            ruleId: 'WEAK_TLS_CONFIGURATION',
            description: 'HTTPS agent with rejectUnauthorized: false - disables certificate validation',
            severity: Severity.HIGH,
            filePath: context.filePath,
            line: i + 1,
            snippet: lines[i].trim(),
            suggestion: 'Never disable certificate validation in production. Remove rejectUnauthorized: false.',
          });
        }
      }
    }

    // Check for weak ciphers
    const weakCiphers = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon'];
    for (const cipher of weakCiphers) {
      if (content.includes(cipher) && content.toLowerCase().includes('cipher')) {
        findings.push({
          ruleId: 'WEAK_TLS_CONFIGURATION',
          description: `Weak cipher suite detected: ${cipher}`,
          severity: Severity.MEDIUM,
          filePath: context.filePath,
          line: 1,
          suggestion: `Remove weak cipher ${cipher}. Use strong ciphers like AES-GCM, ChaCha20-Poly1305.`,
        });
        break;
      }
    }

    return findings;
  },
};

export const networkRules: RuleGroup = {
  category: RuleCategory.NETWORK,
  rules: [
    insecureHttpUrlRule, 
    insecureWebViewRule,
    noRequestTimeoutRule,
    weakTlsConfigurationRule,
  ],
};
