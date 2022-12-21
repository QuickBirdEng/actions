const core = require('@actions/core');
const minimatch = require('minimatch');
const parse = require('lcov-parse');
const fs = require('fs');

function run() {
  const lcovPath = core.getInput('path');
  const minCoverage = core.getInput('min_coverage');
  const filesToExclude = core.getInput('exclude');
  const excludedFiles = filesToExclude.split(' ');

  if (canParse(lcovPath)) {
    core.setFailed('lcov file is empty!');
    return;
  }

  core.info(`Parsing lcov file: ${lcovPath}...`)

  parse(lcovPath, (err, data) => {
    if(err) {
      core.setFailed('Error: Unable to parse lcov file! ' + err);
      return;
    }


    if (typeof data === 'undefined') {
      core.setFailed('Data (undefined): Unable to parse lcov file! ' + data);
      return;
    }

    const linesMissingCoverage = [];

    let totalFinds = 0;
    let totalHits = 0;
    data.forEach((element) => {
      if (shouldCalculateCoverageForFile(element['file'], excludedFiles)) {
        totalFinds += element['lines']['found'];
        totalHits += element['lines']['hit'];

        for (const lineDetails of element['lines']['details']) {
          const hits = lineDetails['hit'];

          if (hits === 0) {
            const fileName = element['file'];
            const lineNumber = lineDetails['line'];
            linesMissingCoverage[fileName] =
              linesMissingCoverage[fileName] || [];
            linesMissingCoverage[fileName].push(lineNumber);
          }
        }
      }
    });
    const coverage = (totalHits / totalFinds) * 100;
    const isValidBuild = coverage >= minCoverage;
    const linesMissingCoverageByFile = Object.entries(linesMissingCoverage).map(
      ([file, lines]) => {
        return `- ${file}: ${lines.join(', ')}`;
      }
    );
    let linesMissingCoverageMessage =
      `Lines not covered:\n` +
      linesMissingCoverageByFile.map((line) => `  ${line}`).join('\n');
    if (!isValidBuild) {
      core.setFailed(
        `${coverage} is less than min_coverage ${minCoverage}\n\n` +
          linesMissingCoverageMessage
      );
    } else {
      var resultMessage = `Coverage: ${coverage}%.\n`;
      if (coverage < 100) {
        resultMessage += linesMissingCoverageMessage;
      }
      core.info(resultMessage);
    }
  });
}

function shouldCalculateCoverageForFile(fileName, excludedFiles) {
  for (let i = 0; i < excludedFiles.length; i++) {
    const isExcluded = minimatch(fileName, excludedFiles[i]);
    if (isExcluded) {
      core.debug(`Excluding ${fileName} from coverage`);
      return false;
    }
  }
  return true;
}

function canParse(path) {
  return fs.existsSync(path) && fs.readFileSync(path).length === 0
}

run();