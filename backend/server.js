require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const connectDB = require('./config/db'); 
const cveRoutes = require('./routes/cveRoutes');
const syncCveData = require('./services/syncService');

const app = express();

app.use(express.json());

app.use(cors());

app.use('/api/cves', cveRoutes);

connectDB();

syncCveData();

app.get('/', (req, res) => {
    res.send('Backend is running successfully!');
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Internal Server Error', error: err.message });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
