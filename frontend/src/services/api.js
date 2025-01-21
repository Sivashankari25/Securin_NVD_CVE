import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api/cves';

export const getCves = (params) => axios.get(`${API_BASE_URL}/list`, { params });

export const getCveDetails = (cveId) =>
  axios.get(`${API_BASE_URL}/${cveId}`);
