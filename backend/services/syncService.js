const axios = require('axios');
const {MongoClient} = require('mongodb');

function pause(milliseconds) {
    return new Promise(resolve => setTimeout(resolve, milliseconds));
}

const headers = {
    'Content-Type': 'application/json',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    "User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36"
}

const generateRequests = async() => {

    //Getting total number of requests
    let res = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1&startIndex=0', {headers: headers});
    console.log(res.data.totalResults);
    const requests = [];
    let initialIndex = 0;
    for(let i=0; i<(res.data.totalResults/2000)+1; i++) {
        requests.push(axios.get(`https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=2000&startIndex=${initialIndex}`, {headers: headers}));
        initialIndex += 2000;
        if(i%3 == 0){
            await pause(32000); // Rolling window of 30 sec
        }
        
    }
    return requests;
}

const syncCveData = async () => {
    try {
        console.log("Starting CVE data sync...");
        const requests = await generateRequests();
        const responses = await Promise.all(requests);

        const client = new MongoClient(process.env.MONGO_URI);
        await client.connect();

        const db = client.db('crud');
        const collection = db.collection('cves');

        for(let i of responses){
            for(let j of i.data.vulnerabilities){
    
                await collection.findOneAndUpdate(
                    { cveId: j.cve.id },
                    j.cve,
                    { upsert: true, new: true }
                );
            }
        }

        console.log("CVE data synced successfully!");
        await pause(21600000); // Next update in 6 hours
        syncCveData();
        
    } catch (error) {
        console.error("Error syncing CVE data:", error);
    }
};

module.exports = syncCveData;