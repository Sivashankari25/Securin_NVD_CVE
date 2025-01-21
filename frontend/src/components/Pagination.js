import React from 'react';
import './App.css';


const Pagination = ({ total, limit, currentPage, onPageChange }) => {
  const pages = Math.ceil(total / limit);
  const pageNumbers = [...Array(pages).keys()].map((n) => n + 1);

  return (
    <div className="pagination">
      {pageNumbers.map((page) => (
        <button
          key={page}
          className={currentPage === page ? 'active' : ''}
          onClick={() => onPageChange(page)}
        >
          {page}
        </button>
      ))}
    </div>
  );
};

export default Pagination;




