import React, { useState, useEffect } from 'react';
import 'bootstrap/dist/css/bootstrap.min.css';
import './App.css';
import Filters from '../src/components/Filters.js';

const App = () => {
    const [cveList, setCveList] = useState([]);
    const [totalRecords, setTotalRecords] = useState(0);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);
    const [resultsPerPage, setResultsPerPage] = useState(10);
    const [currentPage, setCurrentPage] = useState(0);
    const [sortOrder, setSortOrder] = useState('desc');

    // Filters state
    const [filters, setFilters] = useState({
        year: '',
        score: '',
        modifiedDays: '',
    });

    const fetchCveData = async (filterParams = {}) => {
        setIsLoading(true);
        try {
            const { year, score, modifiedDays } = filterParams;
            const queryString = new URLSearchParams({
                resultsPerPage,
                startIndex: currentPage * resultsPerPage,
                ...(year && { year }),
                ...(score && { score }),
                ...(modifiedDays && { modifiedDays }),
                sortOrder
            }).toString();

            const response = await fetch(
                `http://localhost:5000/api/cves?${queryString}`
            );
            if (!response.ok) {
                throw new Error(`API call failed with status ${response.status}`);
            }
            const data = await response.json();
            setCveList(data.vulnerabilities || []);
            console.log(data)
            setTotalRecords(data.totalResults || 0);
        } catch (err) {
            setError(err.message);
        } finally {
            setIsLoading(false);
        }
    };

    const handleRowClick = (cveId) => {
        window.location.href = `/cves/${cveId}`;
    };

    const handleFilterChange = (e) => {
        setFilters({
            ...filters,
            [e.target.name]: e.target.value,
        });
    };

    const handleClearFilters = () => {
        setFilters({
            year: '',
            score: '',
            modifiedDays: '',
        });
    };

    const handleSearch = () => {
        fetchCveData(filters);
    };

    const totalPages = Math.ceil(totalRecords / resultsPerPage);

    useEffect(() => {
        fetchCveData(filters);
    }, [filters, resultsPerPage, currentPage, sortOrder]);

    return (
        <div className="container mt-4 cve-container">
            <h1 className="text-center mb-4 cve-title">CVE List</h1>

            {/* Filters Section */}
            <Filters
                filters={filters}
                onFilterChange={handleFilterChange}
                onClearFilters={handleClearFilters}
                onSearch={handleSearch}
            />

            {/* Results */}
            <div className="row mb-3 align-items-center d-flex justify-content-between">
              <div className="col-md-3 total-records">
                  <strong>Total Records:</strong> {totalRecords}
              </div>
              <div className="col-md-3 text-end">
                  <label className="form-label">
                      Sort Order:
                      <select
                          className="form-select d-inline-block w-auto ms-2"
                          value={sortOrder}
                          onChange={(e) => setSortOrder(e.target.value)}
                      >
                          <option value="asc">Ascending</option>
                          <option value="desc">Descending</option>
                      </select>
                  </label>
              </div>
              <div className="col-md-3 text-end">
                  <label className="form-label results-label">
                      Results Per Page:
                      <select
                          className="form-select results-select"
                          value={resultsPerPage}
                          onChange={(e) => setResultsPerPage(Number(e.target.value))}
                      >
                          <option value={10}>10</option>
                          <option value={50}>50</option>
                          <option value={100}>100</option>
                      </select>
                  </label>
              </div>
            </div>


            {isLoading ? (
                <div className="text-center loader">
                    <div className="spinner-border" role="status">
                        <span className="visually-hidden">Loading...</span>
                    </div>
                </div>
            ) : error ? (
                <div className="alert alert-danger" role="alert">
                    Error: {error}
                </div>
            ) : cveList.length > 0 ? (
                <div className="table-responsive">
                    <table className="table table-bordered table-hover cve-table">
                        <thead className="table-dark">
                            <tr>
                                <th>CVE ID</th>
                                <th>IDENTIFIER</th>
                                <th>PUBLISHED DATE</th>
                                <th>LAST MODIFIED DATE</th>
                                <th>STATUS</th>
                            </tr>
                        </thead>
                        <tbody>
                            {cveList.map((vulnerability) => (
                                <tr
                                    key={vulnerability.cveId}
                                    onClick={() => handleRowClick(vulnerability.cveId)}
                                    className="cve-row"
                                    style={{ cursor: 'pointer' }}
                                >
                                    <td>{vulnerability.cveId}</td>
                                    <td>{vulnerability.descriptions[0].value}</td>
                                    <td>{new Date(vulnerability.publishedDate).toLocaleDateString()}</td>
                                    <td>{new Date(vulnerability.lastModifiedDate).toLocaleDateString()}</td>
                                    <td>{vulnerability.metrics.cvssMetricV2[0]?.baseSeverity || 'Unknown'}</td>
                                </tr>
                                    ))}
                            </tbody>
                    </table>
                </div>
            ) : (
                <div className="alert alert-warning no-data" role="alert">
                    No data available...
                </div>
            )}

            {/* Pagination */}
            <div className="d-flex justify-content-center mt-3 pagination-buttons">
                <nav aria-label="Page navigation">
                    <ul className="pagination">
                        {/* Previous Button */}
                        <li className={`page-item ${currentPage === 0 ? 'disabled' : ''}`}>
                            <button
                                className="page-link"
                                onClick={() => setCurrentPage((prev) => Math.max(prev - 1, 0))}
                                disabled={currentPage === 0}
                            >
                                Previous
                            </button>
                        </li>

                        {/* Page Numbers */}
                        {Array.from({ length: totalPages }, (_, index) => index)
                            .filter(
                                (index) =>
                                    index >= Math.max(0, currentPage - 4) &&
                                    index <= Math.min(totalPages - 1, currentPage + 4)
                            )
                            .map((index) => (
                                <li
                                    key={index}
                                    className={`page-item ${currentPage === index ? 'active' : ''}`}
                                >
                                    <button
                                        className="page-link"
                                        onClick={() => setCurrentPage(index)}
                                    >
                                        {index + 1}
                                    </button>
                                </li>
                            ))}

                        {/* Next Button */}
                        <li
                            className={`page-item ${
                                currentPage + 1 >= totalPages ? 'disabled' : ''
                            }`}
                        >
                            <button
                                className="page-link"
                                onClick={() =>
                                    setCurrentPage((prev) =>
                                        Math.min(prev + 1, totalPages - 1)
                                    )
                                }
                                disabled={currentPage + 1 >= totalPages}
                            >
                                Next
                            </button>
                        </li>
                    </ul>
                </nav>
            </div>
        </div>
    );
};

export default App;


