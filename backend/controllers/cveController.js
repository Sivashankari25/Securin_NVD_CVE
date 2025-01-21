const axios = require('axios');
const Cve = require('../models/Cve');

const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

const getCves = async (req, res) => {
  const { cveId, year, score, lastModified } = req.query;

  try {
    // Building query based on filters
    const query = {};

    if (cveId) query.cveId = cveId;
    if (year) query['publishedDate'] = { $regex: `^${year}` };
    if (score) query['metrics.cvssMetricV2.cvssData.baseScore'] = parseFloat(score);
    if (lastModified) {
      const date = new Date();
      date.setDate(date.getDate() - parseInt(lastModified));
      query.lastModifiedDate = { $gte: date.toISOString() };
    }

    // Fetching CVE data from the database
    const cves = await Cve.find(query).limit(100);
    res.status(200).json(cves);
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ message: 'Error fetching CVEs', error: error.message });
  }
};

// Fetch a single CVE by its ID
const getCveById = async (req, res) => {
  const { cveId } = req.params;

  try {
    const cve = await Cve.findOne({ cveId });

    if (!cve) {
      return res.status(404).json({ message: 'CVE not found' });
    }

    res.status(200).json(cve);
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ message: 'Error fetching CVE', error: error.message });
  }
};

module.exports = { getCves, getCveById };
