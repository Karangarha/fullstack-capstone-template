import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import "bootstrap/dist/css/bootstrap.min.css";
import { urlConfig } from "../../config";

function SearchPage() {
  //Task 1: Define state variables for the search query, age range, and search results.
  const [searchResults, setSearchResults] = useState([]);
  const [searchQuery, setSearchQuery] = useState("");
  cosnst[(ageRange, setAgeRange)] = useState(6);

  const categories = ["Living", "Bedroom", "Bathroom", "Kitchen", "Office"];
  const conditions = ["New", "Like New", "Older"];

  useEffect(() => {
    // fetch all products
    const fetchProducts = async () => {
      try {
        let url = `${urlConfig.backendUrl}/api/gifts`;
        console.log(url);
        const response = await fetch(url);
        if (!response.ok) {
          //something went wrong
          throw new Error(`HTTP error; ${response.status}`);
        }
        const data = await response.json();
        setSearchResults(data);
      } catch (error) {
        console.log("Fetch error: " + error.message);
      }
    };

    fetchProducts();
  }, []);

  // Task 2. Fetch search results from the API based on user inputs.

  const handleSearch = async () => {
    let baseUrl = `${urlConfig.backendUrl}/api/search?`;
    const queryParams = new URLSearchParams({
      name: searchQuery,
      age_year: ageRange,
      categories: document.getElementById("categories").value,
      conditions: document.getElementById("conditions").value,
    }).toString();

    try {
      const response = await fetch(`${baseUrl}${queryParams}`);
      if (!response.ok) {
        throw new Error(`HTTP error; ${response.status}`);
      }
      const data = await response.json();
      setSearchResults(data);
    } catch (error) {
      console.error("Failed to fetch search results:", error);
    }
  };

  const navigate = useNavigate();

  const goToDetailsPage = (productId) => {
    navigate(`app/product/${productId}`);
  };

  return (
    <div className="container mt-5">
      <div className="row justify-content-center">
        <div className="col-md-6">
          <div className="filter-section mb-3 p-3 border rounded">
            <h5>Filters</h5>
            <div className="d-flex flex-column">
              {/* Task 3: Dynamically generate category and condition dropdown options.*/}
              <label htmlFor="categorySelect">Category:</label>
              <select id="categorySelect" className="form-control my-1">
                <option>
                  {categories.map((category, index) => (
                    <option key={index} value={category}>
                      {category}
                    </option>
                  ))}
                </option>
              </select>

              {/* Task 4: Implement an age range slider and display the selected value. */}
              <label htmlFor="ageRange">Age:</label>
              <input
                type="range"
                className="form-control-range"
                id="ageRange"
                max={10}
                min={1}
                value={ageRange}
                onChange={(e) => setAgeRange(e.target.value)}
              />
            </div>
          </div>
          {/* Task 7: Add text input field for search criteria*/}

          <input
            type="text"
            value={searchQuery}
            className="form-coontrol mb-2"
            placeholder="search for items...."
            onChange={(e) => setSearchQuery(e.target.value)}
          />

          {/* Task 8: Implement search button with onClick event to trigger search:*/}

          <button className="btn btn-primary" onClick={handleSearch}>
            Search
          </button>

          {/*Task 5: Display search results and handle empty results with a message. */}

          <div className="search-results mt-4">
            {searchResults.length > 0 ? (
              searchResults.map((product) => (
                <div key={product.id} className="card mb-3">
                  {/* Check if product has an image and display it */}
                  <img
                    src={product.image}
                    alt={product.name}
                    className="card-img-top"
                  />
                  <div className="card-body">
                    <h5 className="card-title">{product.name}</h5>
                    <p className="card-text">
                      {product.description.slice(0, 100)}...
                    </p>
                  </div>
                  <div className="card-footer">
                    <button
                      onClick={() => goToDetailsPage(product.id)}
                      className="btn btn-primary"
                    >
                      View More
                    </button>
                  </div>
                </div>
              ))
            ) : (
              <div className="alert alert-info" role="alert">
                No products found. Please revise your filters.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default SearchPage;
