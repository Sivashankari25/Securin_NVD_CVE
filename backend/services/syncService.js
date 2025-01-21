const axios = require('axios');
const Cve = require('../models/Cve');

// First we will Fetch data from API
const syncCveData = async () => {
    try {
        console.log("Starting CVE data sync...");
        const apiUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
        const params = { resultsPerPage: 10, startIndex: 0 }; 

        const response = await axios.get(apiUrl, { params });

        if (!response.data || !response.data.vulnerabilities) {
            throw new Error("Invalid API response structure");
        }

        const vulnerabilities = response.data.vulnerabilities;

        for (const vuln of vulnerabilities) {
            const cveData = {
                cveId: vuln.cve.id,
                description: vuln.cve.descriptions.find((desc) => desc.lang === 'en')?.value || 'No description available',
                publishedDate: vuln.cve.published,
                lastModified: vuln.cve.lastModified,
                status: vuln.cve.vulnStatus,
            };

            await Cve.findOneAndUpdate(
                { cveId: cveData.cveId },
                cveData,
                { upsert: true, new: true }
            );
        }

        console.log("CVE data synced successfully!");
    } catch (error) {
        console.error("Error syncing CVE data:", error.message);
    }
};

module.exports = syncCveData;
