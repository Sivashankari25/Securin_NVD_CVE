import React, { useState, useEffect } from 'react';
import { getCves } from '../services/api';
import Pagination from './Pagination';
import Filters from './Filters';
import { useNavigate } from 'react-router-dom';

const CveList = () => {
  const [cves, setCves] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [limit] = useState(10);
  const [filters, setFilters] = useState({});
  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      const params = { page, limit, ...filters };
      const { data } = await getCves(params);
      setCves(data.cves);
      setTotal(data.total);
    };
    fetchData();
  }, [page, limit, filters]);

  const handleRowClick = (cveId) => {
    navigate(`/cves/${cveId}`);
  };

  return (
    <div className="cve-list">
      <h1>CVE List</h1>
      <Filters filters={filters} onFiltersChange={setFilters} />
      <table>
        <thead>
          <tr>
            <th>CVE ID</th>
            <th>IDENTIFIER</th>
            <th>PUBLISHED DATE</th>
            <th>LAST MODIFIED DATE</th>
            <th>STATUS</th>
          </tr>
        </thead>
        <tbody>
          {cves.map((cve) => (
            <tr key={cve.cveId} onClick={() => handleRowClick(cve.cveId)}>
              <td>{cve.cveId}</td>
              <td>{cve.description}</td>
              <td>{new Date(cve.publishedDate).toLocaleDateString()}</td>
              <td>{new Date(cve.lastModifiedDate).toLocaleDateString()}</td>
              <td>{cve.status || 'Unknown'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <Pagination
        total={total}
        limit={limit}
        currentPage={page}
        onPageChange={setPage}
      />
    </div>
  );
};

export default CveList;

