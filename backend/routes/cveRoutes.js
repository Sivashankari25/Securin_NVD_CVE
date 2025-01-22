const express = require('express');
const router = express.Router();
const axios = require('axios');
const { MongoClient } = require('mongodb');


router.get('/', async (req, res) => {
    const {
        resultsPerPage = 10,
        startIndex = 0,
        sortBy = 'published',
        sortOrder = 'desc',
        year,
        score,
        modifiedDays
    } = req.query;

    try {
        const client = new MongoClient(process.env.MONGO_URI);
        await client.connect();

        const db = client.db('crud');
        const collection = db.collection('cves');

        const sortDirection = sortOrder === 'asc' ? 1 : -1;

        // Build query
        const query = {};
        if (year) {
            query.cveId = { $regex: year, $options: 'i' };
        }
        if (score) {
            query['metrics.cvssMetricV2.cvssData.baseScore'] = Number(score);
        }
        if (modifiedDays) {
            const dateThreshold = new Date();
            dateThreshold.setDate(dateThreshold.getDate() - Number(modifiedDays));
            query.$expr = {
                $gte: [
                    {
                        $dateFromString: {
                            dateString: "$lastModified",
                            format: "%Y-%m-%dT%H:%M:%S.%L"
                        }
                    },
                    dateThreshold
                ]
            };
        }
        // ...existing code...
        console.log(query);


        const data = await collection
            .find(query)
            .sort({ [sortBy]: sortDirection })
            .skip(Number(startIndex))
            .limit(Number(resultsPerPage))
            .toArray();

        const totalResults = await collection.countDocuments(query);

        res.json({ totalResults, vulnerabilities: data });
    } catch (error) {
        console.error('Error fetching CVE data:', error.message);
        res.status(500).json({ message: 'Error fetching CVE data' });
    }
});


//store


router.post('/store', async (req, res) => { // Ensure the function is async
    const { apiUrl } = req.body; // API URL is sent in the request body

    if (!apiUrl) {
        return res.status(400).json({ message: 'API URL is required' });
    }

    try {
        // Fetch data from the provided API URL
        const response = await axios.get(apiUrl);

        if (!response.data || !response.data.vulnerabilities) {
            return res.status(400).json({ message: 'Invalid data format from API' });
        }

        const vulnerabilities = response.data.vulnerabilities;

        const client = new MongoClient(process.env.MONGO_URI);
        await client.connect();

        const db = client.db('crud');
        const collection = db.collection('cves');

        // Prepare data for insertion
        const cveData = vulnerabilities.map(vuln => {
            const cve = vuln.cve;
            return {
                cveId: cve.id,
                sourceIdentifier: cve.sourceIdentifier,
                publishedDate: cve.published,
                lastModifiedDate: cve.lastModified,
                vulnStatus: cve.vulnStatus || 'N/A',
                descriptions: cve.descriptions?.map(desc => ({
                    lang: desc.lang,
                    value: desc.value,
                })) || [],
                metrics: {
                    cvssMetricV2: cve.metrics.cvssMetricV2?.map(metric => ({
                        source: metric.source,
                        type: metric.type,
                        cvssData: {
                            version: metric.cvssData.version,
                            vectorString: metric.cvssData.vectorString,
                            baseScore: metric.cvssData.baseScore,
                            accessVector: metric.cvssData.accessVector,
                            accessComplexity: metric.cvssData.accessComplexity,
                            authentication: metric.cvssData.authentication,
                            confidentialityImpact: metric.cvssData.confidentialityImpact,
                            integrityImpact: metric.cvssData.integrityImpact,
                            availabilityImpact: metric.cvssData.availabilityImpact,
                        },
                        baseSeverity: metric.baseSeverity,
                        exploitabilityScore: metric.exploitabilityScore,
                        impactScore: metric.impactScore,
                        acInsufInfo: metric.acInsufInfo,
                        obtainAllPrivilege: metric.obtainAllPrivilege,
                        obtainUserPrivilege: metric.obtainUserPrivilege,
                        obtainOtherPrivilege: metric.obtainOtherPrivilege,
                        userInteractionRequired: metric.userInteractionRequired,
                    })) || [],
                },
                weaknesses: cve.weaknesses?.map(weakness => ({
                    source: weakness.source,
                    type: weakness.type,
                    description: weakness.description?.map(desc => ({
                        lang: desc.lang,
                        value: desc.value,
                    })) || [],
                })) || [],
                configurations: cve.configurations?.map(config => ({
                    nodes: config.nodes?.map(node => ({
                        operator: node.operator,
                        negate: node.negate,
                        cpeMatch: node.cpeMatch?.map(cpe => ({
                            vulnerable: cpe.vulnerable,
                            criteria: cpe.criteria,
                            matchCriteriaId: cpe.matchCriteriaId,
                        })) || [],
                    })) || [],
                })) || [],
                references: cve.references?.map(ref => ({
                    url: ref.url,
                    source: ref.source,
                })) || [],
            };
        });

        // Insert data into the database
        const insertResult = await collection.insertMany(cveData, { ordered: false });

        res.json({
            message: 'Data successfully stored in the database',
            insertedCount: insertResult.insertedCount,
        });
    } catch (error) {
        console.error('Error storing data:', error.message);
        res.status(500).json({ message: 'Error storing data', error: error.message });
    }
});




// Endpoint for a specific CVE
router.get('/:cveId', async (req, res) => {
    const { cveId } = req.params;

    try {
        const client = new MongoClient(process.env.MONGO_URI);
        await client.connect();

        const db = client.db('crud');
        const collection = db.collection('cves');
        const data = await collection.findOne({ cveId: cveId });
        res.json(data);
    } catch (error) {
        console.error('Error fetching specific CVE:', error.message);
        res.status(500).json({ message: 'Error fetching specific CVE' });
    }
});


router.get("/year/:year", async (req, res) => {
    const { year } = req.params;

    try {
        const client = new MongoClient(process.env.MONGO_URI);
        await client.connect();

        const db = client.db('crud');
        const collection = db.collection('cves');
        const data = await collection.find({ published: { $regex: year, $options: 'i' } }).toArray()
        res.json(data)

    } catch (error) {
        console.error('Error fetching specific CVE:', error.message);
        res.status(500).json({ message: 'Error fetching specific year' });
    }


})

router.get('/score/:score', async (req, res) => {
    const { score } = req.params; // Extract the score from the URL parameter

    try {
        const client = new MongoClient(process.env.MONGO_URI);
        await client.connect();

        const db = client.db('crud');
        const collection = db.collection('cves');

        // Find CVEs matching the provided score
        const data = await collection.find({ score: Number(score) }).toArray();

        res.json({
            totalResults: data.length,
            vulnerabilities: data,
        });
    } catch (error) {
        console.error('Error fetching CVE data by score:', error.message);
        res.status(500).json({ message: 'Error fetching CVE data by score' });
    }
});


router.get("/modified/:days", async (req, res) => {
    const { days } = req.params;

    try {
        const client = new MongoClient(process.env.MONGO_URI);
        await client.connect();

        const db = client.db('crud');
        const collection = db.collection('cves');

        const dateThreshold = new Date();
        dateThreshold.setDate(dateThreshold.getDate() - days);

        const query = {
            lastModified: { $gte: dateThreshold.toISOString() }
        };

        const data = await collection.find(query).toArray();
        res.json(data)

    } catch (error) {
        console.error('Error fetching specific CVE:', error.message);
        res.status(500).json({ message: 'Error fetching specific year' });
    }
})

module.exports = router;