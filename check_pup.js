const puppeteer = require('puppeteer');

var domain_name = process.argv.slice(2)[0];
(async () => {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    try{
        await page.goto(domain_name);
        await page.screenshot({path: 'example.png'});
        await browser.close();
    } catch (e) {
        console.log("There was an error: ");
        console.log(e);
        page.close();
        browser.close();
        
        
        }
})();

