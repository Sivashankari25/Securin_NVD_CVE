const mongoose = require('mongoose');

const cveSchema = new mongoose.Schema(
  {
    cveId: {
      type: String,
      required: true,
      unique: true,
    },
    description: {
      type: String,
      required: true,
    },
    publishedDate: {
      type: Date,
      required: true,
    },
    lastModifiedDate: {
      type: Date,
      required: true,
    },
    source: {
      type: String,
    },
    cvssMetrics: [
      {
        version: { type: String },
        vectorString: { type: String },
        baseScore: { type: Number },
        baseSeverity: { type: String },
      },
    ],
    weaknesses: [
      {
        description: { type: String },
      },
    ],
    references: [
      {
        url: { type: String },
        name: { type: String },
        source: { type: String },
      },
    ],
  },
  {
    timestamps: true, // Automatically creates `createdAt` and `updatedAt`
  }
);

module.exports = mongoose.model('Cve', cveSchema);
