class SimpleStoryReporter {
  onBegin(config, suite) {
    console.log(`
🚀 Starting E2E Stories...
`);
  }

  onTestBegin(test) {
    // Print the suite hierarchy
    const path = test.titlePath();
    // path[0] is root, path[1] is file, path[2] is top-level describe...
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

  onTestEnd(test, result) {
    const suitesCount = test.titlePath().length - 3;
    if (result.status === 'passed') {
      console.log(`${'  '.repeat(suitesCount + 1)}✅ Success!
`);
    } else {
      console.log(`${'  '.repeat(suitesCount + 1)}❌ Failed: ${result.error?.message}
`);
    }
  }

  onEnd(result) {
    console.log(`✨ Finished: ${result.status === 'passed' ? 'ALL PASSED' : 'FAILED'}
`);
  }
}

module.exports = SimpleStoryReporter;
