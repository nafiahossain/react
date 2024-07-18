import { useState } from 'react'
//import reactLogo from './assets/react.svg'
//import viteLogo from '/vite.svg'
import './App.css'

function App() {
  const [expandedSearchVisible, setExpandedSearchVisible] = useState(false);
  const [regionFlexVisible, setRegionFlexVisible] = useState(false);
  const [calendarVisible, setCalendarVisible] = useState(false);
  const [isCheckIn, setIsCheckIn] = useState(true);

  const handleNavbarSearchClick = () => {
    setExpandedSearchVisible(!expandedSearchVisible);
    setRegionFlexVisible(false);
    setRegionFlexVisible(false);
  };

  const handleSearchDestinationsClick = () => {
    setRegionFlexVisible(!regionFlexVisible);
  };

  const handleCheckInClick = () => {
    setIsCheckIn(true);
    setCalendarVisible(true);
  };
  

  return (
    <div>
      <nav className="navbar">
        <div className="navbar-search-container">
          <button id="anywhere-btn-id" className="anywhere-btn-class" onClick={handleNavbarSearchClick}>Anywhere</button>
          <p>|</p>
          <button id="anyweek-btn-id" className="anywhere-btn-class" onClick={handleNavbarSearchClick}>Any week</button>
          <p>|</p>
          <input type="text" className="search-input" placeholder="Add guests" onClick={handleNavbarSearchClick} />
          <button className="search-button" id="guest-search-button" onClick={handleNavbarSearchClick}>
            <img src="images/search.png" alt="Search" width="15" />
          </button>
        </div>
        <div className="menu-icons">
          <div className="menu-icon">🌐</div>
          <div className="menu-icon">☰</div>
          <div className="menu-icon">👤</div>
        </div>
      </nav>
      {expandedSearchVisible && (
        <div className="expanded-container">
          <div className="expanded-search" id="expanded-search">
            <div className="search-options">
              <button id="search-destinations-btn" onClick={handleSearchDestinationsClick}><strong>Where</strong><br />Search destinations</button>
              <p>|</p>
              <button id="check-in-btn" onClick={handleCheckInClick}><strong>Check in</strong><br />Add dates</button>
              <p>|</p>
              <button id="check-out-btn"><strong>Check out</strong><br />Add dates</button>
              <p>|</p>
              <button id="whoButton"><strong>Who</strong><br />Add guests</button>
              <button id="search-btn">Search</button>
            </div>
          </div>
        </div>
      )}
      {regionFlexVisible && (
        <div className="region-flex" id="region-flex">
          <h3>Search by region</h3>
          <div className="region-items">
            <div className="region-item" id="flexible">
              <img src="images/map1.png" alt="Flexible" />
              <p>I'm flexible</p>
            </div>
            <div className="region-item" id="southeast-asia">
              <img src="images/map2.png" alt="Southeast Asia" />
              <p>Southeast Asia</p>
            </div>
            <div className="region-item" id="canada">
              <img src="images/map3.png" alt="Canada" />
              <p>Canada</p>
            </div>
            <div className="region-item" id="europe">
              <img src="images/map4.png" alt="Europe" />
              <p>Europe</p>
            </div>
            <div className="region-item" id="thailand">
              <img src="images/map5.png" alt="Thailand" />
              <p>Thailand</p>
            </div>
            <div className="region-item" id="midle-east">
              <img src="images/map6.png" alt="Middle East" />
              <p>Middle East</p>
            </div>
          </div>
        </div>
      )}
      {
        
      }
    </div>
  );
}

export default App;
