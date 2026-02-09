class SimpleStoryReporter {
  onBegin(config, suite) {
    console.log('\n🚀 Starting E2E Stories...');
  }

  onTestBegin(test) {
    const path = test.titlePath();
    const suites = path.slice(2, path.length - 1);
    if (suites.length > 0 && !test._suiteLogged) {
      suites.forEach((s, i) => console.log(`${'  '.repeat(i)}📦 ${s}`));
      test._suiteLogged = true;
    }
    console.log(`${'  '.repeat(suites.length)}🎬 Story: ${test.title}`);
  }

  onStepEnd(test, result, step) {
    if (step.category === 'test.step') {
      const suitesCount = test.titlePath().length - 3;
      console.log(`${'  '.repeat(suitesCount + 1)}  ✨ ${step.title}`);
    }
  }

  onStdOut(chunk, test, result) {
    if (process.env.VERBOSE) {
      process.stdout.write(chunk);
    }
  }

  onTestEnd(test, result) {
    const suitesCount = test.titlePath().length - 3;
    if (result.status === 'passed') {
      console.log(`${'  '.repeat(suitesCount + 1)}✅ Success!\n`);
    } else {
      console.log(`${'  '.repeat(suitesCount + 1)}❌ Failed: ${result.error?.message}\n`);
    }
  }

  onEnd(result) {
    console.log(`✨ Finished: ${result.status === 'passed' ? 'ALL PASSED' : 'FAILED'}\n`);
  }
}

module.exports = SimpleStoryReporter;
