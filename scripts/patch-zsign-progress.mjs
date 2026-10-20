import fs from 'node:fs';

const filename = process.argv[2];
if (!filename) {
  console.error('Usage: node patch-zsign-progress.mjs <path-to-src/bundle.cpp>');
  process.exit(2);
}
let source = fs.readFileSync(filename, 'utf8');
if (source.includes('CountZsignProgressOps')) {
  console.log('zsign progress instrumentation already present; leaving source unchanged.');
  process.exit(0);
}

function replaceExactlyOnce(needle, replacement, label) {
  const count = source.split(needle).length - 1;
  if (count !== 1) {
    throw new Error(`Expected exactly one upstream source anchor for ${label}; found ${count}. Refusing to build an incorrectly patched signer.`);
  }
  source = source.replace(needle, replacement);
}

replaceExactlyOnce(
  '#include "sys/types.h"\n',
  '#include "sys/types.h"\n\n' +
  '// xsigner instrumentation: report completed signing operations without changing signing decisions.\n' +
  'static unsigned long long gXsignProgressTotal = 0;\n' +
  'static unsigned long long gXsignProgressDone = 0;\n\n' +
  'static unsigned long long CountZsignProgressOps(jvalue& node)\n' +
  '{\n' +
  '\tunsigned long long total = 1; // one final bundle executable/seal operation per node\n' +
  '\tif (node.has("files")) {\n' +
  '\t\ttotal += static_cast<unsigned long long>(node["files"].size());\n' +
  '\t}\n' +
  '\tif (node.has("folders")) {\n' +
  '\t\tfor (size_t i = 0; i < node["folders"].size(); ++i) {\n' +
  '\t\t\ttotal += CountZsignProgressOps(node["folders"][i]);\n' +
  '\t\t}\n' +
  '\t}\n' +
  '\treturn total;\n' +
  '}\n\n' +
  'static void PrintZsignProgress()\n' +
  '{\n' +
  '\tif (gXsignProgressTotal == 0) return;\n' +
  '\tZLog::PrintV(">>> Progress: %llu/%llu\\n", gXsignProgressDone, gXsignProgressTotal);\n' +
  '\tfflush(stdout); // force the live progress line through Docker pipes immediately\n' +
  '}\n',
  'the include section'
);

replaceExactlyOnce(
  '\t\t\t} else {\n' +
  '\t\t\t\tZLog::WarnV(">>> Warning: Skipping non-Mach-O file: \\t%s\\n", strFile.c_str());\n' +
  '\t\t\t}\n' +
  '\t\t}\n' +
  '\t}\n\n' +
  '\tif (jvNode.has("folders")) {',
  '\t\t\t} else {\n' +
  '\t\t\t\tZLog::WarnV(">>> Warning: Skipping non-Mach-O file: \\t%s\\n", strFile.c_str());\n' +
  '\t\t\t}\n' +
  '\t\t\t++gXsignProgressDone;\n' +
  '\t\t\tPrintZsignProgress();\n' +
  '\t\t}\n' +
  '\t}\n\n' +
  '\tif (jvNode.has("folders")) {',
  'the per-file signing loop'
);

replaceExactlyOnce(
  '\tif (!macho.Sign(m_pSignAsset, bForceSign, strBundleId, strInfoSHA1, strInfoSHA256, strCodeResData)) {\n' +
  '\t\treturn false;\n' +
  '\t}\n\n' +
  '\treturn true;\n' +
  '}',
  '\tif (!macho.Sign(m_pSignAsset, bForceSign, strBundleId, strInfoSHA1, strInfoSHA256, strCodeResData)) {\n' +
  '\t\treturn false;\n' +
  '\t}\n' +
  '\t++gXsignProgressDone;\n' +
  '\tPrintZsignProgress();\n\n' +
  '\treturn true;\n' +
  '}',
  'the bundle signing completion point'
);

replaceExactlyOnce(
  '\tZLog::PrintV(">>> ReadCache: \\t%s\\n", m_bForceSign ? "NO" : "YES");\n' +
  '\tif (SignNode(jvRoot)) {',
  '\tZLog::PrintV(">>> ReadCache: \\t%s\\n", m_bForceSign ? "NO" : "YES");\n' +
  '\tgXsignProgressTotal = CountZsignProgressOps(jvRoot);\n' +
  '\tgXsignProgressDone = 0;\n' +
  '\tZLog::PrintV(">>> Progress: 0/%llu\\n", gXsignProgressTotal);\n' +
  '\tif (SignNode(jvRoot)) {',
  'the signing start point'
);

fs.writeFileSync(filename, source);
console.log('Patched upstream zsign bundle.cpp with operation-count progress output.');
