const express = require('express');
const router = express.Router();
const axios = require('axios');

router.get('/', async (req, res) => {
    const { resultsPerPage = 10, startIndex = 0, sortBy = 'publishedDate', sortOrder = 'desc' } = req.query;

    try {
        const response = await axios.get(
            `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=${resultsPerPage}&startIndex=${startIndex}`
        );

        // Sorting results
        let vulnerabilities = response.data.vulnerabilities || [];
        vulnerabilities.sort((a, b) => {
            const dateA = new Date(a.cve[sortBy]);
            const dateB = new Date(b.cve[sortBy]);
            return sortOrder === 'asc' ? dateA - dateB : dateB - dateA;
        });

        res.json({
            totalResults: response.data.totalResults,
            vulnerabilities,
        });
    } catch (error) {
        console.error('Error fetching CVE data:', error.message);
        res.status(500).json({ message: 'Error fetching CVE data' });
    }
});

// Endpoint for a specific CVE
router.get('/:cveId', async (req, res) => {
    const { cveId } = req.params;

    try {
        const response = await axios.get(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`);
        const vulnerabilities = response.data?.vulnerabilities || [];

        if (vulnerabilities.length > 0) {
            res.json(vulnerabilities[0].cve);
        } else {
            res.status(404).json({ message: 'CVE not found' });
        }
    } catch (error) {
        console.error('Error fetching specific CVE:', error.message);
        res.status(500).json({ message: 'Error fetching specific CVE' });
    }
});

router.get("/year/:year", async (req, res) => {
    const { year } = req.params;

    try {
        const response = await axios.get(
            `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100&startIndex=0`
        );

        // Filter vulnerabilities by year in the published field
        const vulnerabilities = response.data.vulnerabilities || [];
        const filteredVulnerabilities = vulnerabilities.filter(vuln => {
            const publishedDate = new Date(vuln.cve.publishedDate);
            return publishedDate.getFullYear().toString() === year;
        });

        res.json(filteredVulnerabilities);
    } catch (error) {
        console.error('Error fetching CVE data by year:', error.message);
        res.status(500).json({ message: 'Error fetching CVE data by year' });
    }
});


// Fetch CVEs by score
router.get('/score/:score', async (req, res) => {
    const { score } = req.params;

    try {
        const response = await axios.get(
            `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100&startIndex=0`
        );

        const vulnerabilities = response.data.vulnerabilities || [];
        const filteredVulnerabilities = vulnerabilities.filter(vuln => 
            vuln.cve.metrics.cvssMetricV2.cvssData.baseScore === Number(score)
        );

        res.json({
            totalResults: filteredVulnerabilities.length,
            vulnerabilities: filteredVulnerabilities,
        });
    } catch (error) {
        console.error('Error fetching CVE data by score:', error.message);
        res.status(500).json({ message: 'Error fetching CVE data by score' });
    }
});

// Fetch CVEs modified in the last X days
router.get("/modified/:days", async (req, res) => {
    const { days } = req.params;

    try {
        const response = await axios.get(
            `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100&startIndex=0`
        );

        const vulnerabilities = response.data.vulnerabilities || [];
        const dateThreshold = new Date();
        dateThreshold.setDate(dateThreshold.getDate() - days);

        const filteredVulnerabilities = vulnerabilities.filter(vuln => {
            const lastModifiedDate = new Date(vuln.cve.lastModifiedDate);
            return lastModifiedDate >= dateThreshold;
        });

        res.json(filteredVulnerabilities);
    } catch (error) {
        console.error('Error fetching CVE data by modification date:', error.message);
        res.status(500).json({ message: 'Error fetching CVE data by modification date' });
    }
});


module.exports = router;
