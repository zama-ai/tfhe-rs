import puppeteer from 'puppeteer';
import process from 'process';
import * as fs from 'node:fs';

const benchmark_dir = __dirname + '/benchmark_results';
if (!fs.existsSync(benchmark_dir)){
    fs.mkdirSync(benchmark_dir);
}

function isRoot() {
    return process.getuid && process.getuid() === 0;
}

async function runActualTest(page, buttonId) {
    const buttonSelector = `input#${buttonId}`
    const successCheckBoxSelector = `input#testSuccess`
    const benchmarkResultsSelector = `input#benchmarkResults`

    const testSuccessCheckbox = await page.waitForSelector(
        successCheckBoxSelector
    );
    const benchmarkResultsTextbox = await page.waitForSelector(
        benchmarkResultsSelector
    );
    await page.waitForSelector(buttonSelector)

    const isCheckedBefore = await testSuccessCheckbox?.evaluate(el => el.checked);
    expect(isCheckedBefore).toBe(false);

    await page.waitForFunction("document.querySelector('div#loader').hidden");

    await page.waitForSelector(buttonSelector)
    await page.click(buttonSelector);

    await page.waitForFunction("document.getElementById('loader').hidden");

    const isCheckedAfter = await testSuccessCheckbox?.evaluate(el => el.checked);
    expect(isCheckedAfter).toBe(true);

    const results = await benchmarkResultsTextbox?.evaluate(el => el.value);
    if (results) {
        const parsed_results = JSON.parse(results);
        fs.writeFileSync(`${benchmark_dir}/${buttonId}.json`, results, {'flag': 'w'});
    }
}

async function runTestAttachedToButton(buttonId) {
    let browser
    if (isRoot()) {
        browser = await puppeteer.launch({
            headless: "new",
            args: ['--no-sandbox'],
        });
    } else {
        browser = await puppeteer.launch({
            headless: "new",
        });
    }

    let page = await browser.newPage();

    await page.goto('http://localhost:3000');
    page.on('console', msg => console.log('PAGE LOG:', msg.text()));
 
    await page.reload({ waitUntil: ["networkidle0", "domcontentloaded"] });

    let errorCaught = null;
    try {
        await runActualTest(page, buttonId)
    } catch (error) { 
        errorCaught = error
    }
    await page.reload({ waitUntil: ["networkidle0", "domcontentloaded"] });
    await browser.close();

    if (errorCaught != null) {
        throw errorCaught;
    }
}

module.exports = { runTestAttachedToButton };
