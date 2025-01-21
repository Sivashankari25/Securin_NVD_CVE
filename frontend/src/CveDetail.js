import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import './cveDetails.css';

const CveDetail = () => {
    const { cveId } = useParams();
    const [cveData, setCveData] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchCveDetail = async () => {
            try {
                const response = await fetch(`http://localhost:5000/api/cves/${cveId}`);
                if (!response.ok) {
                    throw new Error(`API call failed with status ${response.status}`);
                }

                const data = await response.json();
                setCveData(data);
            } catch (err) {
                setError(err.message);
            } finally {
                setIsLoading(false);
            }
        };

        fetchCveDetail();
    }, [cveId]);

    if (isLoading) return <p>Loading... <br /><br />Please wait for a while.</p>;
    if (error) return <p style={{ color: 'red' }}>{error}</p>;

    return (
        <div style={{ padding: '20px', fontFamily: 'serif', backgroundColor: '#fffaf0', minHeight: '100vh' }}>
            <h1 style={{ textAlign: 'center', fontWeight: 'bold' }}>{cveId}</h1>
            {cveData ? (
                <div>
                    <section>
                        <h3 style={{ fontWeight: 'bold' }}>DESCRIPTION:</h3>
                        <p>{cveData.descriptions[0]?.value}</p>
                        <section>
                            <h3 style={{ fontWeight: 'bold' }}>CVSS V2 Metrics:</h3>
                            <div>
                                <p>
                                    <strong>Severity:</strong> {cveData.metrics.cvssMetricV2[0].baseSeverity || "N/A"} <br />
                                    <strong>Score:</strong> {cveData.metrics.cvssMetricV2[0].cvssData.baseScore || "N/A"} <br />
                                    <strong>Vector String:</strong> {cveData.metrics.cvssMetricV2[0].cvssData.vectorString || "N/A"}
                                </p>
                            </div>
                        </section>
                        {cveData.metrics.cvssMetricV2.map((metric, index) => (
                            <table key={index} style={{ width: '100%', border: '2px solid black', marginBottom: '20px', borderCollapse: 'collapse' }}>
                                <thead>
                                    <tr>
                                        <th style={{ border: '2px solid black', fontWeight: 'bold' }}>Access Vector</th>
                                        <th style={{ border: '2px solid black', fontWeight: 'bold' }}>Access Complexity</th>
                                        <th style={{ border: '2px solid black', fontWeight: 'bold' }}>Authentication</th>
                                        <th style={{ border: '2px solid black', fontWeight: 'bold' }}>Confidentiality Impact</th>
                                        <th style={{ border: '2px solid black', fontWeight: 'bold' }}>Integrity Impact</th>
                                        <th style={{ border: '2px solid black', fontWeight: 'bold' }}>Availability Impact</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td style={{ border: '2px solid black', fontWeight: 'bold' }}>{metric.cvssData.accessVector}</td>
                                        <td style={{ border: '2px solid black', fontWeight: 'bold' }}>{metric.cvssData.accessComplexity}</td>
                                        <td style={{ border: '2px solid black', fontWeight: 'bold' }}>{metric.cvssData.authentication}</td>
                                        <td style={{ border: '2px solid black', fontWeight: 'bold' }}>{metric.cvssData.confidentialityImpact}</td>
                                        <td style={{ border: '2px solid black', fontWeight: 'bold' }}>{metric.cvssData.integrityImpact}</td>
                                        <td style={{ border: '2px solid black', fontWeight: 'bold' }}>{metric.cvssData.availabilityImpact}</td>
                                    </tr>
                                </tbody>
                            </table>
                        ))}
                    </section>

                    <section>
                        <h3 style={{ fontWeight: 'bold' }}>SCORES:</h3>
                        {cveData.metrics.cvssMetricV2.map((metric, index) => (
                            <div key={index}>
                                <p><strong>Exploitability Score:</strong> {metric.exploitabilityScore}</p>
                                <p><strong>Impact Score:</strong> {metric.impactScore}</p>
                            </div>
                        ))}
                    </section>

                    <section>
                        <h3 style={{ fontWeight: 'bold' }}>CPE:</h3>
                        {cveData.configurations.map((config, idx) => (
                            <table key={idx} style={{ width: '100%', border: '2px solid black', marginBottom: '20px', borderCollapse: 'collapse' }}>
                                <thead>
                                    <tr>
                                        <th style={{ border: '2px solid black', fontWeight: 'bold' }}>Criteria</th>
                                        <th style={{ border: '2px solid black', fontWeight: 'bold' }}>Match Criteria ID</th>
                                        <th style={{ border: '2px solid black', fontWeight: 'bold' }}>Vulnerable</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {config.nodes.map((node, index) =>
                                        node.cpeMatch.map((cpe, i) => (
                                            <tr key={`${index}-${i}`}>
                                                <td style={{ border: '2px solid black', fontWeight: 'bold' }}>{cpe.criteria}</td>
                                                <td style={{ border: '2px solid black', fontWeight: 'bold' }}>{cpe.matchCriteriaId}</td>
                                                <td style={{ border: '2px solid black', fontWeight: 'bold' }}>{cpe.vulnerable ? 'Yes' : 'No'}</td>
                                            </tr>
                                        ))
                                    )}
                                </tbody>
                            </table>
                        ))}
                    </section>
                </div>
            ) : (
                <p>No data available for this CVE.</p>
            )}
        </div>
    );
};

export default CveDetail;
