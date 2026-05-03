const fs = require('fs');
let c = fs.readFileSync('backend.js', 'utf8');

const regex = /\} else \{\s*analysis\.summary = `Heuristic scan complete\. High risk indicators detected\. Score: \$\{analysis\.score\}\/100\. Potential security incident - immediate investigation warranted\.`;\s*\} else \{\s*analysis\.summary = `Heuristic scan complete\. High risk indicators detected\. Score: \$\{analysis\.score\}\/100\. Potential security incident - immediate investigation warranted\.`;\s*\}/g;

const replacement = `} else {
      analysis.summary = \`Heuristic scan complete. High risk indicators detected. Score: \${analysis.score}/100. Potential security incident - immediate investigation warranted.\`;
    }`;

c = c.replace(regex, replacement);
fs.writeFileSync('backend.js', c);
