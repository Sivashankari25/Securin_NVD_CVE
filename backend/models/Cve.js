// const mongoose = require('mongoose');

// const cveSchema = new mongoose.Schema(
//   {
//     cveId: {
//       type: String,
//       required: true,
//       unique: true,
//     },
//     description: {
//       type: String,
//       required: true,
//     },
//     publishedDate: {
//       type: Date,
//       required: true,
//     },
//     lastModifiedDate: {
//       type: Date,
//       required: true,
//     },
//     source: {
//       type: String,
//     },
//     cvssMetrics: [
//       {
//         version: { type: String },
//         vectorString: { type: String },
//         baseScore: { type: Number },
//         baseSeverity: { type: String },
//       },
//     ],
//     weaknesses: [
//       {
//         description: { type: String },
//       },
//     ],
//     references: [
//       {
//         url: { type: String },
//         name: { type: String },
//         source: { type: String },
//       },
//     ],
//   },
//   {
//     timestamps: true,
//   }
// );

// module.exports = mongoose.model('Cve', cveSchema);
const mongoose = require('mongoose');

const cveSchema = new mongoose.Schema(
  {
    cveId: {
      type: String,
      required: true,
      unique: true,
    },
    sourceIdentifier: {
      type: String,
    },
    publishedDate: {
      type: Date,
      required: true,
    },
    lastModifiedDate: {
      type: Date,
      required: true,
    },
    vulnStatus: {
      type: String,
    },
    descriptions: [
      {
        lang: { type: String },
        value: { type: String },
      },
    ],
    metrics: {
      cvssMetricV2: [
        {
          source: { type: String },
          type: { type: String },
          cvssData: {
            version: { type: String },
            vectorString: { type: String },
            baseScore: { type: Number },
            accessVector: { type: String },
            accessComplexity: { type: String },
            authentication: { type: String },
            confidentialityImpact: { type: String },
            integrityImpact: { type: String },
            availabilityImpact: { type: String },
          },
          baseSeverity: { type: String },
          exploitabilityScore: { type: Number },
          impactScore: { type: Number },
          acInsufInfo: { type: Boolean },
          obtainAllPrivilege: { type: Boolean },
          obtainUserPrivilege: { type: Boolean },
          obtainOtherPrivilege: { type: Boolean },
          userInteractionRequired: { type: Boolean },
        },
      ],
    },
    weaknesses: [
      {
        source: { type: String },
        type: { type: String },
        description: [
          {
            lang: { type: String },
            value: { type: String },
          },
        ],
      },
    ],
    configurations: [
      {
        nodes: [
          {
            operator: { type: String },
            negate: { type: Boolean },
            cpeMatch: [
              {
                vulnerable: { type: Boolean },
                criteria: { type: String },
                matchCriteriaId: { type: String },
              },
            ],
          },
        ],
      },
    ],
    references: [
      {
        url: { type: String },
        source: { type: String },
      },
    ],
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model('Cve', cveSchema);
