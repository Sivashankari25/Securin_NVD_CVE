import React from 'react';
import ReactDOM from 'react-dom';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import App from './App.js';
import CveDetail from './CveDetail.js';

ReactDOM.render(
    <BrowserRouter>
        <Routes>
            <Route path="/" element={<App />} />
            <Route path="/cves/:cveId" element={<CveDetail />} />
        </Routes>
    </BrowserRouter>,
    document.getElementById('root')
);
