import React from 'react';
import './filter.css';

const Filters = ({ filters, onFilterChange, onClearFilters, onSearch }) => {
  return (
    <div className="filters-card">
      <div className="filters-grid">
        <div className="filter-group">
          <label className="filter-label">Year</label>
          <input
            type="text"
            className="filter-input"
            name="year"
            placeholder="e.g: 2023"
            value={filters.year}
            onChange={onFilterChange}
          />
        </div>
        <div className="filter-group">
          <label className="filter-label">CVSS Score</label>
          <input
            type="number"
            className="filter-input"
            name="score"
            placeholder="e.g: 7.2"
            min="0"
            max="10"
            step="0.1"
            value={filters.score}
            onChange={onFilterChange}
          />
        </div>
        <div className="filter-group">
          <label className="filter-label">Modified (days)</label>
          <input
            type="number"
            className="filter-input"
            name="modifiedDays"
            placeholder="e.g: 30"
            value={filters.modifiedDays}
            onChange={onFilterChange}
          />
        </div>
        <div className="filter-actions">
          <button
            className="clear-filters-btn"
            onClick={onClearFilters}
          >
            Clear Filters
          </button>
          <button
            className="search-filters-btn"
            onClick={onSearch}
          >
            Search
          </button>
        </div>
      </div>
    </div>
  );
};

export default Filters;
