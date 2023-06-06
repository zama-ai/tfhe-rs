import puppeteer from 'puppeteer';
import process from 'process';

function isRoot() {
    return process.getuid && process.getuid() === 0;
}

async function runActualTest(page, buttonId) {
    const buttonSelector = `input#${buttonId}`
    const successCheckBoxSelector = `input#testSuccess`

    const testSuccessCheckbox = await page.waitForSelector(
        successCheckBoxSelector
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
